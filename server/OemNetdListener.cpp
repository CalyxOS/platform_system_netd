/**
 * Copyright (c) 2019, The Android Open Source Project
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

#define LOG_TAG "OemNetd"

#include "OemNetdListener.h"

namespace com {
namespace android {
namespace internal {
namespace net {

::android::sp<OemNetdListener> OemNetdListener::getListenerInternal() {
    return ::android::sp<OemNetdListener>::make();
}

::android::sp<::android::IBinder> OemNetdListener::getListener() {
    // Thread-safe initialization.
    static ::android::sp<OemNetdListener> listener = getListenerInternal();
    static ::android::sp<::android::IBinder> sIBinder = ::android::IInterface::asBinder(listener);
    return sIBinder;
}

::android::sp<IOemNetdEventListener> OemNetdListener::getOemNetdEventListener() {
    std::lock_guard lock(mOemEventMutex);
    if (mOemNetdEventListener == nullptr) {
        ::android::sp<::android::IBinder> b = ::android::defaultServiceManager()->checkService(
                ::android::String16("oem_netd_listener"));
        mOemNetdEventListener = ::android::interface_cast<IOemNetdEventListener>(b);
    }
    return mOemNetdEventListener;
}

::android::binder::Status OemNetdListener::isAlive(bool* alive) {
    *alive = true;
    return ::android::binder::Status::ok();
}

::android::binder::Status OemNetdListener::registerOemUnsolicitedEventListener(
        const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    registerOemUnsolicitedEventListenerInternal(listener);
    listener->onRegistered();
    return ::android::binder::Status::ok();
}

void OemNetdListener::registerOemUnsolicitedEventListenerInternal(
        const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mOemUnsolicitedMutex);

    // Create the death listener.
    class DeathRecipient : public ::android::IBinder::DeathRecipient {
      public:
        DeathRecipient(OemNetdListener* oemNetdListener,
                       ::android::sp<IOemNetdUnsolicitedEventListener> listener)
            : mOemNetdListener(oemNetdListener), mListener(std::move(listener)) {}
        ~DeathRecipient() override = default;
        void binderDied(const ::android::wp<::android::IBinder>& /* who */) override {
            mOemNetdListener->unregisterOemUnsolicitedEventListenerInternal(mListener);
        }

      private:
        OemNetdListener* mOemNetdListener;
        ::android::sp<IOemNetdUnsolicitedEventListener> mListener;
    };
    ::android::sp<::android::IBinder::DeathRecipient> deathRecipient =
            new DeathRecipient(this, listener);

    ::android::IInterface::asBinder(listener)->linkToDeath(deathRecipient);

    mOemUnsolListenerMap.insert({listener, deathRecipient});
}

void OemNetdListener::unregisterOemUnsolicitedEventListenerInternal(
        const ::android::sp<IOemNetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mOemUnsolicitedMutex);
    mOemUnsolListenerMap.erase(listener);
}

}  // namespace net
}  // namespace internal
}  // namespace android
}  // namespace com
