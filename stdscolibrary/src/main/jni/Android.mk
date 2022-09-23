LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := omesStdSco

LOCAL_SRC_FILES :=\
			main.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH) \

include $(LOCAL_PATH)/auth/makefile
include $(LOCAL_PATH)/safelog/makefile
include $(LOCAL_PATH)/probe/makefile
include $(LOCAL_PATH)/urlcheck/makefile

LOCAL_STATIC_LIBRARIES += ext_curl

LOCAL_CFLAGS := -Wall -Wextra -Weverything -Werror,-Wformat-nonliteral
LOCAL_CFLAGS += -Oz -flto -ffunction-sections -fdata-sections -fvisibility=hidden

LOCAL_CONLYFLAGS := -std=c11

LOCAL_LDLIBS := -lz -llog
LOCAL_LDLIBS += -Wl,--version-script=${LOCAL_PATH}/export.map.txt
LOCAL_LDLIBS += -flto -Wl,--exclude-libs,ALL -Wl,--gc-sections
include $(BUILD_SHARED_LIBRARY)

$(call import-add-path, $(LOCAL_PATH)/external)

#$(call import-module,./zlib/prebuilt)
$(call import-module,./openssl/prebuilt)
$(call import-module,./curl/prebuilt)
