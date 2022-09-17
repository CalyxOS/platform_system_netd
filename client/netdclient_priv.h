/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef NETD_CLIENT_NETD_CLIENT_PRIV_H
#define NETD_CLIENT_NETD_CLIENT_PRIV_H

// Max length of uid when formatted as string for abstract socket name prefix.
// Also change format string if changing this.
#define ABSTRACT_SOCKET_NAME_PREFIX_LEN 8
// UID format string, padded to max length (same as above)
#define ABSTRACT_SOCKET_NAME_PREFIX_FMT "%08u"
// Single-character socket name prefix for system apps
#define ABSTRACT_SOCKET_NAME_SYSTEM_PREFIX 'S'

#define ZYGOTE_UID 1000
#define ZYGOTE_APP_PREFIX "com.android.internal.os.AppZygoteInit/"
#define ZYGOTE_WEBVIEW_PREFIX "com.android.internal.os.WebViewZygoteInit/"

int getNetworkForDnsInternal(int fd, unsigned* dnsNetId);

extern "C" {
void netdClientInitDnsOpenProxy(int (**DnsOpenProxyType)());
void netdClientInitSocket(int (**SocketFunctionType)(int, int, int));
}

#endif  // NETD_CLIENT_NETD_CLIENT_PRIV_H
