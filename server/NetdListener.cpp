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
#include "TrafficController.h"

namespace android {
namespace net {

using android::net::TrafficController;
using android::netdutils::ResponseCode;

NetdListener::NetdListener(TrafficController* trafficCtrl) : FrameworkListener(SOCKET_NAME) {
    registerCmd(new Handler(trafficCtrl));
}

NetdListener::Handler::Handler(TrafficController* trafficCtrl) : NetdCommand("netd"),
                                                                 mTrafficCtrl(trafficCtrl) {}

NetdListener::Handler::~Handler() {}


int NetdListener::Handler::runCommand(SocketClient* cli, int argc, char** argv) {
    if (argc < 4) {
        char* msg = nullptr;
        asprintf(&msg, "Invalid number of arguments to netd: %i", argc);
        ALOGW("%s", msg);
        cli->sendMsg(ResponseCode::CommandParameterError, msg, false);
        free(msg);
        return -1;
    }

    if (strcmp(argv[1], "traffic") == 0) {
        if (strcmp(argv[2], "getuidnetworking") == 0) {
            cli->sendCode(mTrafficCtrl->getNetworkingAllowedForUid(std::stoul(argv[3])));
        }
    }

    return 0;
}

}  // namespace net
}  // namespace android
