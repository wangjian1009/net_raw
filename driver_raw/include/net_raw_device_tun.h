#ifndef NET_RAW_DERICE_TUN_H_INCLEDED
#define NET_RAW_DERICE_TUN_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_tun_t
net_raw_device_tun_create(
    net_raw_driver_t driver, const char * name
#if NET_RAW_USE_DEV_NE
    , void *  tunnelFlow
#endif
    );

net_raw_device_tun_t net_raw_device_tun_cast(net_raw_device_t device);

net_address_t net_raw_device_tun_address(net_raw_device_t device);
net_address_t net_raw_device_tun_mask(net_raw_device_t device);

NET_END_DECL

#endif
