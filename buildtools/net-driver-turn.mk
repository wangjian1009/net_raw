net_driver_turn_base:=$(call my-dir)/../driver_turn
net_driver_turn_output:=$(OUTPUT_PATH)/lib/libnet_driver_turn.a
net_driver_turn_cpp_flags:=-I$(net_driver_turn_base)/../depends/lwip/custom \
                           -I$(net_driver_turn_base)/../depends/lwip/src/include \
                           -I$(net_driver_turn_base)/../depends/lwip/src/include/ipv4 \
                           -I$(net_driver_turn_base)/../depends/lwip/src/include/ipv6 \
                           -I$(net_driver_turn_base)/../../cpe/include \
                           -I$(net_driver_turn_base)/../../net/depends/libev/include \
                           -I$(net_driver_turn_base)/../../net/core/include \
                           -I$(net_driver_turn_base)/include
net_driver_turn_src:=$(wildcard $(net_driver_turn_base)/src/*.c)
$(eval $(call def_library,net_driver_turn))
