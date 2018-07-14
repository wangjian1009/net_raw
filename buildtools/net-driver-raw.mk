net_driver_raw_base:=$(call my-dir)/../driver_raw
net_driver_raw_output:=$(OUTPUT_PATH)/lib/libnet_driver_raw.a
net_driver_raw_cpp_flags:=-I$(net_driver_raw_base)/../buildtools/custom/lwip \
                          -I$(net_driver_raw_base)/../depends/lwip/src/include \
                          -I$(net_driver_raw_base)/../depends/lwip/src/include/ipv4 \
                          -I$(net_driver_raw_base)/../depends/lwip/src/include/ipv6 \
                          -I$(net_driver_raw_base)/../../cpe/include \
                          -I$(net_driver_raw_base)/../../net/depends/libev/include \
                          -I$(net_driver_raw_base)/../../net/core/include \
                          -I$(net_driver_raw_base)/include \
                          $(if $(filter 1,$D), -DLWIP_DEBUG)
net_driver_raw_src:=$(wildcard $(net_driver_raw_base)/src/*.c)
$(eval $(call def_library,net_driver_raw))
