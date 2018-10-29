LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := net_driver_tun
LOCAL_EXPORT_CFLAGS += $(if $(filter 0,$(APKD)),,-g)
LOCAL_CFLAGS += $(if $(filter 0,$(APKD)),,-DDEBUG=1)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../depends/lwip/src/include \
                    $(LOCAL_PATH)/../../depends/lwip/src/include/ipv4 \
	            $(LOCAL_PATH)/../../depends/lwip/src/include/ipv6 \
                    $(LOCAL_PATH)/../custom/lwip \
                    $(LOCAL_PATH)/../../../cpe/include \
                    $(LOCAL_PATH)/../../../net/depends/libev/include \
                    $(LOCAL_PATH)/../../../net/core/include \
                    $(LOCAL_PATH)/../../driver_tun/include
LOCAL_LDLIBS := 
LOCAL_SRC_FILES += $(patsubst $(LOCAL_PATH)/%,%,$(wildcard $(LOCAL_PATH)/../../driver_tun/src/*.c))

include $(BUILD_STATIC_LIBRARY)
