/*
 * Copyright (C) 2021 The Calyx Institute
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

#define LOG_TAG "NetdListener"

#include <log/log.h>
#include <netdutils/ResponseCode.h>

#include "NetdListener.h"
#include "NetworkController.h"

using android::netdutils::ResponseCode;

namespace android {
namespace net {

NetdListener::NetdListener(NetworkController* netCtrl) : FrameworkListener(SOCKET_NAME) {
    registerCmd(new Handler(netCtrl));
}

NetdListener::Handler::Handler(NetworkController* netCtrl) : NetdCommand("netd"),
                                                                 mNetCtrl(netCtrl) {}

NetdListener::Handler::~Handler() {}


int NetdListener::Handler::runCommand(SocketClient* cli, int argc, char** argv) {
    if (argc < 5) {
        char* msg = nullptr;
        asprintf(&msg, "Invalid number of arguments to netd: %i", argc);
        ALOGW("%s", msg);
        cli->sendMsg(ResponseCode::CommandParameterError, msg, false);
        free(msg);
        return -1;
    }

    if (strcmp(argv[1], "network") == 0) {
        if (strcmp(argv[2], "getuidnetworking") == 0) {
            cli->sendCode(mNetCtrl->getNetworkAllowedForUser(std::stoul(argv[3]),
                                                             std::stoul(argv[4])));
        }
    }

    return 0;
}

}  // namespace net
}  // namespace android
