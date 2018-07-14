#ifndef NET_RAW_DERICE_TUN_LISTENER_H_INCLEDED
#define NET_RAW_DERICE_TUN_LISTENER_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_tun_listener_t
net_raw_device_tun_listener_create(
    net_raw_device_tun_t device_tun, net_address_t address, net_protocol_t protocol);

void net_raw_device_tun_listener_free(net_raw_device_tun_listener_t tun_listener);

net_raw_device_tun_listener_t
net_raw_device_tun_listener_find(net_raw_device_tun_t device_tun, net_address_t address);

NET_END_DECL

#endif
