#ifndef NET_TUN_DERICE_H_INCLEDED
#define NET_TUN_DERICE_H_INCLEDED
#include "net_tun_types.h"
#if NET_TUN_USE_DEV_NE
#import <NetworkExtension/NEPacketTunnelFlow.h>
#endif

NET_BEGIN_DECL

net_tun_device_t
net_tun_device_create(
    net_tun_driver_t driver, const char * name
#if NET_TUN_USE_DEV_NE
    , NEPacketTunnelFlow * tunnelFlow
#endif
    );

void net_tun_device_free(net_tun_device_t device);

NET_END_DECL

#endif
