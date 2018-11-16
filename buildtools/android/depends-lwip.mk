LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := lwip
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../../cpe/include \
                    $(LOCAL_PATH)/../../depends/lwip/src/include \
                    $(LOCAL_PATH)/../../depends/lwip/src/include/ipv4 \
	            $(LOCAL_PATH)/../../depends/lwip/src/include/ipv6 \
                    $(LOCAL_PATH)/../custom/lwip \

LOCAL_SRC_FILES := $(addprefix ../../depends/lwip/, \
                         src/core/timers.c \
                         src/core/udp.c \
                         src/core/memp.c \
                         src/core/init.c \
                         src/core/pbuf.c \
                         src/core/tcp.c \
                         src/core/tcp_out.c \
                         src/core/sys.c \
                         src/core/netif.c \
                         src/core/def.c \
                         src/core/mem.c \
                         src/core/tcp_in.c \
                         src/core/stats.c \
                         src/core/inet_chksum.c \
                         src/core/ipv4/icmp.c \
                         src/core/ipv4/ip4.c \
                         src/core/ipv4/ip4_addr.c \
                         src/core/ipv4/ip_frag.c \
                         src/core/ipv6/ip6.c \
                         src/core/ipv6/nd6.c \
                         src/core/ipv6/icmp6.c \
                         src/core/ipv6/ip6_addr.c \
                         src/core/ipv6/ip6_frag.c \
                         src/api/err.c \
                    ) \
                    $(addprefix $(LOCAL_PATH)/../custom/lwip/, \
                         sys.c \
                         error.c \
                     )

include $(BUILD_STATIC_LIBRARY)
