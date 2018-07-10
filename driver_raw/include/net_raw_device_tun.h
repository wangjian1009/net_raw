#ifndef NET_RAW_DERICE_TUN_H_INCLEDED
#define NET_RAW_DERICE_TUN_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_tun_t
net_raw_device_tun_create(
    net_raw_driver_t driver, const char * name, net_address_t ip, net_address_t mask);

NET_END_DECL

#endif
