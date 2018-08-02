net_driver_tun_base:=$(call my-dir)/../driver_tun
net_driver_tun_output:=$(OUTPUT_PATH)/lib/libnet_driver_tun.a
net_driver_tun_cpp_flags:=-I$(net_driver_tun_base)/../buildtools/custom/lwip \
                          -I$(net_driver_tun_base)/../depends/lwip/src/include \
                          -I$(net_driver_tun_base)/../depends/lwip/src/include/ipv4 \
                          -I$(net_driver_tun_base)/../depends/lwip/src/include/ipv6 \
                          -I$(net_driver_tun_base)/../../cpe/include \
                          -I$(net_driver_tun_base)/../../net/depends/libev/include \
                          -I$(net_driver_tun_base)/../../net/core/include \
                          -I$(net_driver_tun_base)/include \
                          $(if $(filter 1,$D), -DLWIP_DEBUG)
net_driver_tun_src:=$(wildcard $(net_driver_tun_base)/src/*.c)
$(eval $(call def_library,net_driver_tun))
