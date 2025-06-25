LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE:= libtermux
LOCAL_SRC_FILES:= termux.cpp
LOCAL_LDFLAGS := -Wl,--build-id=none
LOCAL_CFLAGS := -ffile-prefix-map=${ANDROID_HOME}/ndk=ndk -ffile-prefix-map=${PWD}=Exclave
include $(BUILD_SHARED_LIBRARY)
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
