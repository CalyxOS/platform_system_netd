/**
 * Copyright (c) 2022, The Calyx Institute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.net;

/**
 * {@hide}
 */
oneway interface IOemNetdEventListener {

   /**
    * Logs a single bind function call.
    *
    * @param netId the ID of the network the bind was performed on.
    * @param uid the UID of the application that performed the bind.
    */
    void onBindEvent(int netId, int uid);
}
