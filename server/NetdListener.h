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

#ifndef _NETDLISTENER_H__
#define _NETDLISTENER_H__

#include <sysutils/FrameworkListener.h>

#include "NetdCommand.h"
#include "NetworkController.h"

namespace android {
namespace net {

class NetdListener : public FrameworkListener {
public:
    explicit NetdListener(NetworkController* netCtrl);
    virtual ~NetdListener() {}

    static constexpr const char* SOCKET_NAME = "netdl";

private:
    class Handler : public NetdCommand {
    public:
        Handler(NetworkController* netCtrl);
        virtual ~Handler();
        int runCommand(SocketClient *c, int argc, char** argv) override;

    private:
        NetworkController* mNetCtrl;
    };
};

}  // namespace net
}  // namespace android

#endif
