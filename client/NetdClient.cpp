/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "NetdClient.h"

#include <arpa/inet.h>
#include <cutils/misc.h>           // FIRST_APPLICATION_UID
#include <errno.h>
#include <math.h>
#include <resolv.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <random>
#include <string>
#include <vector>

#include <DnsProxydProtocol.h>  // NETID_USE_LOCAL_NAMESERVERS
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>

#define LOG_TAG "NetdClient"
#include <log/log.h>

#include "Fwmark.h"
#include "FwmarkClient.h"
#include "FwmarkCommand.h"
#include "netdclient_priv.h"
#include "netdutils/ResponseCode.h"
#include "netdutils/Stopwatch.h"
#include "netid_client.h"

using android::base::ParseInt;
using android::base::unique_fd;
using android::netdutils::ResponseCode;
using android::netdutils::Stopwatch;

namespace {

// Keep this in sync with CMD_BUF_SIZE in FrameworkListener.cpp.
constexpr size_t MAX_CMD_SIZE = 4096;
// Whether sendto(), sendmsg(), sendmmsg() in libc are shimmed or not. This property is evaluated at
// process start time and cannot change at runtime on a given device.
constexpr char PROPERTY_REDIRECT_SOCKET_CALLS[] = "ro.vendor.redirect_socket_calls";
// Whether some shimmed functions dispatch FwmarkCommand or not. The property can be changed by
// System Server at runtime. Note: accept4(), socket(), connect() are always shimmed.
constexpr char PROPERTY_REDIRECT_SOCKET_CALLS_HOOKED[] = "net.redirect_socket_calls.hooked";

std::atomic_uint netIdForProcess(NETID_UNSET);
std::atomic_uint netIdForResolv(NETID_UNSET);
std::atomic_bool allowNetworkingForProcess(true);

typedef int (*Accept4FunctionType)(int, sockaddr*, socklen_t*, int);
typedef int (*ConnectFunctionType)(int, const sockaddr*, socklen_t);
typedef int (*SocketFunctionType)(int, int, int);
typedef unsigned (*NetIdForResolvFunctionType)(unsigned);
typedef int (*DnsOpenProxyType)();
typedef int (*SendmmsgFunctionType)(int, const mmsghdr*, unsigned int, int);
typedef ssize_t (*SendmsgFunctionType)(int, const msghdr*, unsigned int);
typedef int (*SendtoFunctionType)(int, const void*, size_t, int, const sockaddr*, socklen_t);
typedef int (*BindFunctionType)(int, const sockaddr*, socklen_t);
typedef int (*GetsocknameFunctionType)(int, sockaddr*, socklen_t*);
typedef int (*GetpeernameFunctionType)(int, sockaddr*, socklen_t*);
typedef ssize_t (*RecvfromFunctionType)(int, void*, size_t len, int flags, sockaddr*, socklen_t*);

// These variables are only modified at startup (when libc.so is loaded) and never afterwards, so
// it's okay that they are read later at runtime without a lock.
Accept4FunctionType libcAccept4 = nullptr;
ConnectFunctionType libcConnect = nullptr;
SocketFunctionType libcSocket = nullptr;
SendmmsgFunctionType libcSendmmsg = nullptr;
SendmsgFunctionType libcSendmsg = nullptr;
SendtoFunctionType libcSendto = nullptr;
BindFunctionType libcBind = nullptr;
GetsocknameFunctionType libcGetsockname = nullptr;
GetpeernameFunctionType libcGetpeername = nullptr;
RecvfromFunctionType libcRecvfrom = nullptr;

static bool propertyValueIsTrue(const char* prop_name) {
    char prop_value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(prop_name, prop_value) > 0) {
        if (strcmp(prop_value, "true") == 0) {
            return true;
        }
    }
    return false;
}

static bool redirectSocketCallsIsTrue() {
    static bool cached_result = propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS);
    return cached_result;
}

int checkSocket(int socketFd) {
    if (socketFd < 0) {
        return -EBADF;
    }
    int family;
    socklen_t familyLen = sizeof(family);
    if (getsockopt(socketFd, SOL_SOCKET, SO_DOMAIN, &family, &familyLen) == -1) {
        return -errno;
    }
    if (!FwmarkClient::shouldSetFwmark(family)) {
        return -EAFNOSUPPORT;
    }
    return 0;
}

bool shouldMarkSocket(int socketFd, const sockaddr* dst) {
    // Only mark inet sockets that are connecting to inet destinations. This excludes, for example,
    // inet sockets connecting to AF_UNSPEC (i.e., being disconnected), and non-inet sockets that
    // for some reason the caller wants to attempt to connect to an inet destination.
    return dst && FwmarkClient::shouldSetFwmark(dst->sa_family) && (checkSocket(socketFd) == 0);
}

int closeFdAndSetErrno(int fd, int error) {
    close(fd);
    errno = -error;
    return -1;
}

void fillRandomChars(char* dest, size_t n) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::default_random_engine e(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset));
    for (size_t i = 0; i < n; ++i) {
        dest[i] = charset[dist(e)];
    }
}

void randomizeAbstractSockaddr(sockaddr_un* addr, size_t start, socklen_t* paddrlen) {
    addr->sun_path[0] = '\0';

    size_t maxlen = sizeof(sockaddr_un) - sizeof(sa_family_t) - 1;

    // +1 to skip leading null byte
    if (start + 1 <= maxlen) {
        fillRandomChars(&addr->sun_path[1 + start], maxlen - start);
        *paddrlen = sizeof(sockaddr_un);
    }
}

bool userIsSystem(uid_t uid) {
    return uid < FIRST_APPLICATION_UID;
}
bool userIsSystem() {
    return getuid() < FIRST_APPLICATION_UID;
}

bool isSockaddrAbstract(const sockaddr* addr, socklen_t addrlen) {
    if ((addr != nullptr) && (addr->sa_family == AF_UNIX)) {
        // Is it an abstract socket? sun_path must be >1 bytes and must start with '\0'
        if (((size_t)addrlen > (sizeof(sa_family_t) + 1))
                && ((sockaddr_un*)addr)->sun_path[0] == '\0') {
            return true;
        }
    }
    return false;
}

const char* getAllowedGlobalPrefixIfAny(const sockaddr_un* addr, socklen_t addrlen) {
    std::string_view name(&addr->sun_path[1], addrlen - sizeof(sa_family_t) - 1);
    if (name.starts_with(ZYGOTE_APP_PREFIX)) {
        return ZYGOTE_APP_PREFIX;
    } else if (name.starts_with(ZYGOTE_WEBVIEW_PREFIX)) {
        return ZYGOTE_WEBVIEW_PREFIX;
    }
    return nullptr;
/*    size_t len = addrlen - sizeof(sa_family_t) - 1;
    if ((len >= sizeof(ZYGOTE_APP_PREFIX)-1) && memcmp(ZYGOTE_APP_PREFIX,
            &addr->sun_path[1], sizeof(ZYGOTE_APP_PREFIX)-1) == 0) {
        return ZYGOTE_APP_PREFIX;
    } else if ((len >= sizeof(ZYGOTE_WEBVIEW_PREFIX)-1) && memcmp(ZYGOTE_WEBVIEW_PREFIX,
            &addr->sun_path[1], sizeof(ZYGOTE_WEBVIEW_PREFIX)-1) == 0) {
        return ZYGOTE_WEBVIEW_PREFIX;
    }
    return nullptr;*/
}

void logAbstractSockaddr(const char* str, const sockaddr_un* sa_un, socklen_t addrlen) {
    std::string name(&sa_un->sun_path[1], addrlen - sizeof(sa_family_t) - 1);
    ALOGE("%s: %u: '%s'", str, getuid(), name.c_str());
}

int isolateAbstractSockaddr(const sockaddr_un* addr, socklen_t addrlen,
        sockaddr_un* sa_un, socklen_t* salen) {
    int uid = getuid();
    size_t namelen = addrlen - sizeof(sa_family_t);
    int prefixlen = 0;
    sa_un->sun_path[0] = '\0'; // Abstract sockets must start with '\0'

    if (!userIsSystem(uid)) {
        // Regular user apps get de facto separate namespaces
        prefixlen = ABSTRACT_SOCKET_NAME_PREFIX_LEN;
        snprintf(&sa_un->sun_path[1], ABSTRACT_SOCKET_NAME_PREFIX_LEN + 1,
                ABSTRACT_SOCKET_NAME_PREFIX_FMT, uid);
    } else {
        // System apps all share a single de facto namespace separate from user apps
        //prefixlen = 1;
        //sa_un->sun_path[1] = ABSTRACT_SOCKET_NAME_SYSTEM_PREFIX;
        prefixlen = 0;
    }

    if ((namelen + prefixlen) > sizeof(sa_un->sun_path)) {
        return -1;
    }

    // Concatenate the original abstract socket name without a null terminator
    memcpy(&sa_un->sun_path[1 + prefixlen], &addr->sun_path[1], namelen - 1);
    *salen = addrlen + prefixlen;
    return 0;
}

int reverseIsolateAbstractSockaddr(sockaddr_un* addr, socklen_t* addrlen) {
    int uid = getuid();
    size_t namelen = *addrlen - sizeof(sa_family_t);
    int prefixlen = 0;

    if (!userIsSystem(uid)) {
        // Regular user apps
        prefixlen = ABSTRACT_SOCKET_NAME_PREFIX_LEN;
    } else if (uid != 0) {
        // System apps
        //prefixlen = 1;
        prefixlen = 0;
    }
    if ((namelen - prefixlen) <= 0) {
        return -1;
    }

    // Remove the prefix from the abstract socket name
    memmove(&addr->sun_path[1], &addr->sun_path[1 + prefixlen], namelen);
    *addrlen = *addrlen - prefixlen;
    return 0;
}

int netdClientAccept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) {
    int acceptedSocket = libcAccept4(sockfd, addr, addrlen, flags);
    if (acceptedSocket == -1) {
        return -1;
    }
    int family;
    if (addr) {
        family = addr->sa_family;
    } else {
        socklen_t familyLen = sizeof(family);
        if (getsockopt(acceptedSocket, SOL_SOCKET, SO_DOMAIN, &family, &familyLen) == -1) {
            return closeFdAndSetErrno(acceptedSocket, -errno);
        }
    }
    if (FwmarkClient::shouldSetFwmark(family)) {
        FwmarkCommand command = {FwmarkCommand::ON_ACCEPT, 0, 0, 0};
        if (int error = FwmarkClient().send(&command, acceptedSocket, nullptr)) {
            return closeFdAndSetErrno(acceptedSocket, error);
        }
    }
    return acceptedSocket;
}

int netdClientConnect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    bool isSystem = userIsSystem();
    bool isAbstract = isSockaddrAbstract(addr, addrlen);

    if (isAbstract) {
        logAbstractSockaddr("netdClientConnect", (sockaddr_un*)addr, addrlen);

        if (!isSystem) {
            const char* global_prefix = getAllowedGlobalPrefixIfAny((sockaddr_un*)addr, addrlen);

            // Forbid non-system uids from connecting to the allowed global prefixes
            if (global_prefix != nullptr) {
                errno = -EACCES;
                return -1;
            }
        }
    }

    const bool shouldSetFwmark = shouldMarkSocket(sockfd, addr);
    if (shouldSetFwmark) {
        FwmarkCommand command = {FwmarkCommand::ON_CONNECT, 0, 0, 0};
        int error;
        if (redirectSocketCallsIsTrue()) {
            FwmarkConnectInfo connectInfo(0, 0, addr);
            error = FwmarkClient().send(&command, sockfd, &connectInfo);
        } else {
            error = FwmarkClient().send(&command, sockfd, nullptr);
        }

        if (error) {
            errno = -error;
            return -1;
        }
    }

    // Latency measurement does not include time of sending commands to Fwmark
    Stopwatch s;
    int ret = libcConnect(sockfd, addr, addrlen);
    // Save errno so it isn't clobbered by sending ON_CONNECT_COMPLETE
    int connectErrno = errno;

    // If we failed to connect to the specified socket, and it is a UNIX abstract socket,
    // we want to try again in the app's own namespace. We also want to hide the reason for
    // the failure as EPERM to prevent global socket discovery.
    if (!isSystem && (ret != 0) /*&& (connectErrno == ECONNREFUSED)*/
            && isAbstract) {
        struct sockaddr_un sa_un = {
                .sun_family = AF_UNIX,
                .sun_path = "\0",
        };

        connectErrno = EACCES;

        if (isolateAbstractSockaddr((sockaddr_un*)addr, addrlen, &sa_un, &addrlen) == 0) {
            logAbstractSockaddr("netdClientConnect isolated", &sa_un, addrlen);
            ret = libcConnect(sockfd, (sockaddr*)&sa_un, addrlen);
            connectErrno = errno;
        }
    }

    const auto latencyMs = static_cast<unsigned>(s.timeTakenUs() / 1000);
    // Send an ON_CONNECT_COMPLETE command that includes sockaddr and connect latency for reporting
    if (shouldSetFwmark) {
        FwmarkConnectInfo connectInfo(ret == 0 ? 0 : connectErrno, latencyMs, addr);
        // TODO: get the netId from the socket mark once we have continuous benchmark runs
        FwmarkCommand command = {FwmarkCommand::ON_CONNECT_COMPLETE, /* netId (ignored) */ 0,
                                 /* uid (filled in by the server) */ 0, 0};
        // Ignore return value since it's only used for logging
        FwmarkClient().send(&command, sockfd, &connectInfo);
    }
    errno = connectErrno;
    return ret;
}

int netdClientSocket(int domain, int type, int protocol) {
    // Block creating AF_INET/AF_INET6 socket if networking is not allowed.
    if (FwmarkCommand::isSupportedFamily(domain) && !allowNetworkingForProcess.load()) {
        errno = EPERM;
        return -1;
    }
    int socketFd = libcSocket(domain, type, protocol);
    if (socketFd == -1) {
        return -1;
    }
    unsigned netId = netIdForProcess & ~NETID_USE_LOCAL_NAMESERVERS;
    if (netId != NETID_UNSET && FwmarkClient::shouldSetFwmark(domain)) {
        if (int error = setNetworkForSocket(netId, socketFd)) {
            return closeFdAndSetErrno(socketFd, error);
        }
    }
    return socketFd;
}

int netdClientSendmmsg(int sockfd, const mmsghdr* msgs, unsigned int msgcount, int flags) {
    if (propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS_HOOKED) && !checkSocket(sockfd)) {
        const sockaddr* addr = nullptr;
        if ((msgcount > 0) && (msgs != nullptr) && (msgs[0].msg_hdr.msg_name != nullptr)) {
            addr = reinterpret_cast<const sockaddr*>(msgs[0].msg_hdr.msg_name);
            if ((addr != nullptr) && (FwmarkCommand::isSupportedFamily(addr->sa_family))) {
                FwmarkConnectInfo sendmmsgInfo(0, 0, addr);
                FwmarkCommand command = {FwmarkCommand::ON_SENDMMSG, 0, 0, 0};
                FwmarkClient().send(&command, sockfd, &sendmmsgInfo);
            }
        }
    }
    return libcSendmmsg(sockfd, msgs, msgcount, flags);
}

ssize_t netdClientSendmsg(int sockfd, const msghdr* msg, unsigned int flags) {
    if (propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS_HOOKED) && !checkSocket(sockfd)) {
        const sockaddr* addr = nullptr;
        if ((msg != nullptr) && (msg->msg_name != nullptr)) {
            addr = reinterpret_cast<const sockaddr*>(msg->msg_name);
            if ((addr != nullptr) && (FwmarkCommand::isSupportedFamily(addr->sa_family))) {
                FwmarkConnectInfo sendmsgInfo(0, 0, addr);
                FwmarkCommand command = {FwmarkCommand::ON_SENDMSG, 0, 0, 0};
                FwmarkClient().send(&command, sockfd, &sendmsgInfo);
            }
        }
    }
    return libcSendmsg(sockfd, msg, flags);
}

int netdClientSendto(int sockfd, const void* buf, size_t bufsize, int flags, const sockaddr* addr,
                     socklen_t addrlen) {
    if (propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS_HOOKED) && !checkSocket(sockfd)) {
        if ((addr != nullptr) && (FwmarkCommand::isSupportedFamily(addr->sa_family))) {
            FwmarkConnectInfo sendtoInfo(0, 0, addr);
            FwmarkCommand command = {FwmarkCommand::ON_SENDTO, 0, 0, 0};
            FwmarkClient().send(&command, sockfd, &sendtoInfo);
        }
    }
    return libcSendto(sockfd, buf, bufsize, flags, addr, addrlen);
}

int netdClientBind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    bool isAbstract = isSockaddrAbstract(addr, addrlen);
    if (isAbstract) {
        logAbstractSockaddr("netdClientBind", (sockaddr_un*)addr, addrlen);
    }

    if (!userIsSystem() && isAbstract) {
        struct sockaddr_un sa_un = {
                .sun_family = AF_UNIX,
                .sun_path = "\0",
        };
        socklen_t salen = 0;

        // Allowed global prefixes will never fail a bind from a user app, to prevent
        // detection. We make sure of this.
        const char* global_prefix = getAllowedGlobalPrefixIfAny((sockaddr_un*)addr, addrlen);

        if (global_prefix != nullptr) {
            logAbstractSockaddr("netdClientBind prefix match", (sockaddr_un*)addr, addrlen);
            int res = libcBind(sockfd, addr, addrlen);
            ALOGE("netdClientBind: bind called, res %d, errno %d", res, errno);

            if (res != 0) {
                int prefixlen = strlen(global_prefix);
                memcpy(&sa_un.sun_path[1], &((sockaddr_un*)addr)->sun_path[1], prefixlen);
                ALOGE("netdClientBind random...");
                randomizeAbstractSockaddr(&sa_un, prefixlen, &salen);
                ALOGE("netdClientBind randomized.");
                return libcBind(sockfd, (sockaddr*)&sa_un, salen);
            } else {
                ALOGE("netdClientBind prefix bind succeed");
                errno = 0;
                return 0;
            }
        }

        // Because netdClientConnect attempts to connect to a global-namespace socket
        // *before* trying a uid-namespace socket, the behavior here allows a uid to bind
        // with a name that it can *know* is used by something else, if the uid is capable
        // of connecting to the name that it tries to bind to, here. This would be rare.
        // We don't consider this a problem, but a quirk worth tolerating.
        if (isolateAbstractSockaddr((sockaddr_un*)addr, addrlen, &sa_un, &salen) == 0) {
            logAbstractSockaddr("netdClientBind isolated", &sa_un, salen);
            return libcBind(sockfd, (sockaddr*)&sa_un, salen);
        } else {
            errno = -ENAMETOOLONG;
            return -1;
        }
    }
    return libcBind(sockfd, addr, addrlen);
}

int callNetdClientGetname(const char* funcname, GetsocknameFunctionType func,
        int sockfd, sockaddr* addr, socklen_t* paddrlen) {
    socklen_t initial_size = *paddrlen;
    int res = func(sockfd, addr, paddrlen);
    int getnameErrno = errno;
    bool isAbstract = isSockaddrAbstract((sockaddr*)addr, *paddrlen);

    if (!isAbstract) {
        errno = getnameErrno;
        return res;
    }

    if (res != 0) {
        errno = getnameErrno;
        ALOGE("%s: fail: %d %d", funcname, res, errno);
        return res;
    }

    sockaddr_un* sa_un = (sockaddr_un*)addr;

    logAbstractSockaddr(funcname, sa_un, *paddrlen);

    if (!userIsSystem()) {
        const char* global_prefix = getAllowedGlobalPrefixIfAny(sa_un, *paddrlen);

        if (global_prefix != nullptr) {
            //ALOGE("%s: prefix truncate skip", funcname);
            //errno = 0;
            //return 0;
            // No need to randomize, just truncate after the prefix
            size_t prefixlen = strlen(global_prefix);
            // Clean anything after the prefix with A's instead of 0's
            // (Because of the whole "shouldn't be null-terminated" thing)
            size_t remainder = initial_size - prefixlen - sizeof(sa_family_t) - 1;
            if (remainder > 0) {
                memset(&sa_un->sun_path[prefixlen+1], (int)'A', remainder);
                *paddrlen = sizeof(sa_family_t) + 1 + prefixlen;
            }
            logAbstractSockaddr(funcname, sa_un, *paddrlen);
            ALOGE("%s: prefix success? %zu %zu", funcname, prefixlen, sizeof(sa_un->sun_path));
            errno = 0;
            return 0;
        }

        if (reverseIsolateAbstractSockaddr(sa_un, paddrlen) != 0) {
            //logAbstractSockaddr(funcname, &sa_un, salen);
            ALOGE("%s: reverse isolate fail", funcname);
            errno = -EACCES;
            return -1;
        }
    }
    if (isAbstract) {
        logAbstractSockaddr(funcname, sa_un, *paddrlen);
    }
    return res;
}

int netdClientGetsockname(int sockfd, sockaddr* addr, socklen_t* paddrlen) {
    return callNetdClientGetname("netdClientGetsockname", libcGetsockname, sockfd, addr, paddrlen);
}

int netdClientGetpeername(int sockfd, sockaddr* addr, socklen_t* paddrlen) {
    return callNetdClientGetname("netdClientGetpeername", libcGetpeername, sockfd, addr, paddrlen);
}

ssize_t netdClientRecvfrom(int sockfd, void* buf, size_t len, int flags, sockaddr* src_addr,
        socklen_t* src_addr_length) {
    return libcRecvfrom(sockfd, buf, len, flags, src_addr, src_addr_length);
}

unsigned getNetworkForResolv(unsigned netId) {
    if (netId != NETID_UNSET) {
        return netId;
    }
    // Special case for DNS-over-TLS bypass; b/72345192 .
    if ((netIdForResolv & ~NETID_USE_LOCAL_NAMESERVERS) != NETID_UNSET) {
        return netIdForResolv;
    }
    netId = netIdForProcess;
    if (netId != NETID_UNSET) {
        return netId;
    }
    return netIdForResolv;
}

int setNetworkForTarget(unsigned netId, std::atomic_uint* target) {
    const unsigned requestedNetId = netId;
    netId &= ~NETID_USE_LOCAL_NAMESERVERS;

    if (netId == NETID_UNSET) {
        *target = netId;
        return 0;
    }
    // Verify that we are allowed to use |netId|, by creating a socket and trying to have it marked
    // with the netId. Call libcSocket() directly; else the socket creation (via netdClientSocket())
    // might itself cause another check with the fwmark server, which would be wasteful.

    const auto socketFunc = libcSocket ? libcSocket : socket;
    int socketFd = socketFunc(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socketFd < 0) {
        return -errno;
    }
    int error = setNetworkForSocket(netId, socketFd);
    if (!error) {
        *target = requestedNetId;
    }
    close(socketFd);
    return error;
}

int dns_open_proxy() {
    const char* cache_mode = getenv("ANDROID_DNS_MODE");
    const bool use_proxy = (cache_mode == NULL || strcmp(cache_mode, "local") != 0);
    if (!use_proxy) {
        errno = ENOSYS;
        return -1;
    }

    // If networking is not allowed, dns_open_proxy should just fail here.
    // Then eventually, the DNS related functions in local mode will get
    // EPERM while creating socket.
    if (!allowNetworkingForProcess.load()) {
        errno = EPERM;
        return -1;
    }
    const auto socketFunc = libcSocket ? libcSocket : socket;
    int s = socketFunc(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s == -1) {
        return -1;
    }
    const int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    static const struct sockaddr_un proxy_addr = {
            .sun_family = AF_UNIX,
            .sun_path = "/dev/socket/dnsproxyd",
    };

    const auto connectFunc = libcConnect ? libcConnect : connect;
    if (TEMP_FAILURE_RETRY(
                connectFunc(s, (const struct sockaddr*) &proxy_addr, sizeof(proxy_addr))) != 0) {
        // Store the errno for connect because we only care about why we can't connect to dnsproxyd
        int storedErrno = errno;
        close(s);
        errno = storedErrno;
        return -1;
    }

    return s;
}

auto divCeil(size_t dividend, size_t divisor) {
    return ((dividend + divisor - 1) / divisor);
}

// FrameworkListener only does only read() call, and fails if the read doesn't contain \0
// Do single write here
int sendData(int fd, const void* buf, size_t size) {
    if (fd < 0) {
        return -EBADF;
    }

    ssize_t rc = TEMP_FAILURE_RETRY(write(fd, (char*) buf, size));
    if (rc > 0) {
        return rc;
    } else if (rc == 0) {
        return -EIO;
    } else {
        return -errno;
    }
}

int readData(int fd, void* buf, size_t size) {
    if (fd < 0) {
        return -EBADF;
    }

    size_t current = 0;
    for (;;) {
        ssize_t rc = TEMP_FAILURE_RETRY(read(fd, (char*) buf + current, size - current));
        if (rc > 0) {
            current += rc;
            if (current == size) {
                break;
            }
        } else if (rc == 0) {
            return -EIO;
        } else {
            return -errno;
        }
    }
    return 0;
}

bool readBE32(int fd, int32_t* result) {
    int32_t tmp;
    ssize_t n = TEMP_FAILURE_RETRY(read(fd, &tmp, sizeof(tmp)));
    if (n < static_cast<ssize_t>(sizeof(tmp))) {
        return false;
    }
    *result = ntohl(tmp);
    return true;
}

bool readResponseCode(int fd, int* result) {
    char buf[4];
    ssize_t n = TEMP_FAILURE_RETRY(read(fd, &buf, sizeof(buf)));
    if (n < static_cast<ssize_t>(sizeof(buf))) {
        return false;
    }

    // The format of response code is 3 bytes followed by a space.
    buf[3] = '\0';
    if (!ParseInt(buf, result)) {
        errno = EINVAL;
        return false;
    }

    return true;
}

}  // namespace

#define CHECK_SOCKET_IS_MARKABLE(sock) \
    do {                               \
        int err = checkSocket(sock);   \
        if (err) return err;           \
    } while (false)

#define HOOK_ON_FUNC(remoteFunc, nativeFunc, localFunc) \
    do {                                                \
        if ((remoteFunc) && *(remoteFunc)) {            \
            (nativeFunc) = *(remoteFunc);               \
            *(remoteFunc) = (localFunc);                \
        }                                               \
    } while (false)

// accept() just calls accept4(..., 0), so there's no need to handle accept() separately.
extern "C" void netdClientInitAccept4(Accept4FunctionType* function) {
    HOOK_ON_FUNC(function, libcAccept4, netdClientAccept4);
}

extern "C" void netdClientInitConnect(ConnectFunctionType* function) {
    HOOK_ON_FUNC(function, libcConnect, netdClientConnect);
}

extern "C" void netdClientInitSocket(SocketFunctionType* function) {
    HOOK_ON_FUNC(function, libcSocket, netdClientSocket);
}

extern "C" void netdClientInitSendmmsg(SendmmsgFunctionType* function) {
    if (!propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS)) {
        return;
    }
    HOOK_ON_FUNC(function, libcSendmmsg, netdClientSendmmsg);
}

extern "C" void netdClientInitSendmsg(SendmsgFunctionType* function) {
    if (!propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS)) {
        return;
    }
    HOOK_ON_FUNC(function, libcSendmsg, netdClientSendmsg);
}

extern "C" void netdClientInitSendto(SendtoFunctionType* function) {
    if (!propertyValueIsTrue(PROPERTY_REDIRECT_SOCKET_CALLS)) {
        return;
    }
    HOOK_ON_FUNC(function, libcSendto, netdClientSendto);
}

extern "C" void netdClientInitBind(BindFunctionType* function) {
    HOOK_ON_FUNC(function, libcBind, netdClientBind);
}

extern "C" void netdClientInitGetsockname(GetsocknameFunctionType* function) {
    HOOK_ON_FUNC(function, libcGetsockname, netdClientGetsockname);
}

extern "C" void netdClientInitGetpeername(GetpeernameFunctionType* function) {
    HOOK_ON_FUNC(function, libcGetpeername, netdClientGetpeername);
}

extern "C" void netdClientInitRecvfrom(RecvfromFunctionType* function) {
    HOOK_ON_FUNC(function, libcRecvfrom, netdClientRecvfrom);
}

extern "C" void netdClientInitNetIdForResolv(NetIdForResolvFunctionType* function) {
    if (function) {
        *function = getNetworkForResolv;
    }
}

extern "C" void netdClientInitDnsOpenProxy(DnsOpenProxyType* function) {
    if (function) {
        *function = dns_open_proxy;
    }
}

extern "C" int getNetworkForSocket(unsigned* netId, int socketFd) {
    if (!netId || socketFd < 0) {
        return -EBADF;
    }
    Fwmark fwmark;
    socklen_t fwmarkLen = sizeof(fwmark.intValue);
    if (getsockopt(socketFd, SOL_SOCKET, SO_MARK, &fwmark.intValue, &fwmarkLen) == -1) {
        return -errno;
    }
    *netId = fwmark.netId;
    return 0;
}

extern "C" unsigned getNetworkForProcess() {
    return netIdForProcess & ~NETID_USE_LOCAL_NAMESERVERS;
}

extern "C" int setNetworkForSocket(unsigned netId, int socketFd) {
    CHECK_SOCKET_IS_MARKABLE(socketFd);
    FwmarkCommand command = {FwmarkCommand::SELECT_NETWORK, netId, 0, 0};
    return FwmarkClient().send(&command, socketFd, nullptr);
}

extern "C" int setNetworkForProcess(unsigned netId) {
    return setNetworkForTarget(netId, &netIdForProcess);
}

extern "C" int setNetworkForResolv(unsigned netId) {
    return setNetworkForTarget(netId, &netIdForResolv);
}

extern "C" int protectFromVpn(int socketFd) {
    CHECK_SOCKET_IS_MARKABLE(socketFd);
    FwmarkCommand command = {FwmarkCommand::PROTECT_FROM_VPN, 0, 0, 0};
    return FwmarkClient().send(&command, socketFd, nullptr);
}

extern "C" int setNetworkForUser(uid_t uid, int socketFd) {
    CHECK_SOCKET_IS_MARKABLE(socketFd);
    FwmarkCommand command = {FwmarkCommand::SELECT_FOR_USER, 0, uid, 0};
    return FwmarkClient().send(&command, socketFd, nullptr);
}

extern "C" int queryUserAccess(uid_t uid, unsigned netId) {
    FwmarkCommand command = {FwmarkCommand::QUERY_USER_ACCESS, netId, uid, 0};
    return FwmarkClient().send(&command, -1, nullptr);
}

extern "C" int tagSocket(int socketFd, uint32_t tag, uid_t uid) {
    CHECK_SOCKET_IS_MARKABLE(socketFd);
    FwmarkCommand command = {FwmarkCommand::TAG_SOCKET, 0, uid, tag};
    return FwmarkClient().send(&command, socketFd, nullptr);
}

extern "C" int untagSocket(int socketFd) {
    CHECK_SOCKET_IS_MARKABLE(socketFd);
    FwmarkCommand command = {FwmarkCommand::UNTAG_SOCKET, 0, 0, 0};
    return FwmarkClient().send(&command, socketFd, nullptr);
}

extern "C" int setCounterSet(uint32_t, uid_t) {
    return -ENOTSUP;
}

extern "C" int deleteTagData(uint32_t, uid_t) {
    return -ENOTSUP;
}

extern "C" int resNetworkQuery(unsigned netId, const char* dname, int ns_class, int ns_type,
                               uint32_t flags) {
    std::vector<uint8_t> buf(MAX_CMD_SIZE, 0);
    int len = res_mkquery(ns_o_query, dname, ns_class, ns_type, nullptr, 0, nullptr, buf.data(),
                          MAX_CMD_SIZE);

    return resNetworkSend(netId, buf.data(), len, flags);
}

extern "C" int resNetworkSend(unsigned netId, const uint8_t* msg, size_t msglen, uint32_t flags) {
    // Encode
    // Base 64 encodes every 3 bytes into 4 characters, but then adds padding to the next
    // multiple of 4 and a \0
    const size_t encodedLen = divCeil(msglen, 3) * 4 + 1;
    std::string encodedQuery(encodedLen - 1, 0);
    int enLen = b64_ntop(msg, msglen, encodedQuery.data(), encodedLen);

    if (enLen < 0) {
        // Unexpected behavior, encode failed
        // b64_ntop only fails when size is too long.
        return -EMSGSIZE;
    }
    // Send
    netId = getNetworkForResolv(netId);
    const std::string cmd = "resnsend " + std::to_string(netId) + " " + std::to_string(flags) +
                            " " + encodedQuery + '\0';
    if (cmd.size() > MAX_CMD_SIZE) {
        // Cmd size must less than buffer size of FrameworkListener
        return -EMSGSIZE;
    }
    int fd = dns_open_proxy();
    if (fd == -1) {
        return -errno;
    }
    ssize_t rc = sendData(fd, cmd.c_str(), cmd.size());
    if (rc < 0) {
        close(fd);
        return rc;
    }
    shutdown(fd, SHUT_WR);
    return fd;
}

extern "C" int resNetworkResult(int fd, int* rcode, uint8_t* answer, size_t anslen) {
    int32_t result = 0;
    unique_fd ufd(fd);
    // Read -errno/rcode
    if (!readBE32(fd, &result)) {
        // Unexpected behavior, read -errno/rcode fail
        return -errno;
    }
    if (result < 0) {
        // result < 0, it's -errno
        return result;
    }
    // result >= 0, it's rcode
    *rcode = result;

    // Read answer
    int32_t size = 0;
    if (!readBE32(fd, &size)) {
        // Unexpected behavior, read ans len fail
        return -EREMOTEIO;
    }
    if (anslen < static_cast<size_t>(size)) {
        // Answer buffer is too small
        return -EMSGSIZE;
    }
    int rc = readData(fd, answer, size);
    if (rc < 0) {
        // Reading the answer failed.
        return rc;
    }
    return size;
}

extern "C" void resNetworkCancel(int fd) {
    close(fd);
}

extern "C" void setAllowNetworkingForProcess(bool allowNetworking) {
    allowNetworkingForProcess.store(allowNetworking);
}

extern "C" int getNetworkForDns(unsigned* dnsNetId) {
    if (dnsNetId == nullptr) return -EFAULT;
    int fd = dns_open_proxy();
    if (fd == -1) {
        return -errno;
    }
    unique_fd ufd(fd);
    return getNetworkForDnsInternal(fd, dnsNetId);
}

int getNetworkForDnsInternal(int fd, unsigned* dnsNetId) {
    if (fd == -1) {
        return -EBADF;
    }

    unsigned resolvNetId = getNetworkForResolv(NETID_UNSET);

    const std::string cmd = "getdnsnetid " + std::to_string(resolvNetId);
    ssize_t rc = sendData(fd, cmd.c_str(), cmd.size() + 1);
    if (rc < 0) {
        return rc;
    }

    int responseCode = 0;
    // Read responseCode
    if (!readResponseCode(fd, &responseCode)) {
        // Unexpected behavior, read responseCode fail
        return -errno;
    }

    if (responseCode != ResponseCode::DnsProxyQueryResult) {
        return -EOPNOTSUPP;
    }

    int32_t result = 0;
    // Read -errno/dnsnetid
    if (!readBE32(fd, &result)) {
        // Unexpected behavior, read -errno/dnsnetid fail
        return -errno;
    }

    *dnsNetId = result;

    return 0;
}
