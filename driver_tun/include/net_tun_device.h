#ifndef NET_TUN_DERICE_H_INCLEDED
#define NET_TUN_DERICE_H_INCLEDED
#include "net_tun_types.h"
#if NET_TUN_USE_DEV_NE
#import <NetworkExtension/NEPacketTunnelFlow.h>
#endif

NET_BEGIN_DECL

net_tun_device_t
net_tun_device_create(
    net_tun_driver_t driver
#if NET_TUN_USE_DEV_TUN
    , int dev_fd
    , uint16_t dev_mtu
    , net_address_t dev_ipv4_address
    , net_address_t dev_ipv4_mask
    , net_address_t dev_ipv6_address
    , const char * dev_name
#endif    
#if NET_TUN_USE_DEV_NE
    , NEPacketTunnelFlow * tunnelFlow
    , NEPacketTunnelNetworkSettings * settings
#endif
    , net_address_t netif_ipv4_address
    , net_address_t netif_ipv6_address
    );

void net_tun_device_free(net_tun_device_t device);

net_tun_device_t net_tun_device_default(net_tun_driver_t driver);
net_address_t net_tun_device_gen_local_address(net_tun_device_t device);

net_address_t net_tun_device_ipv4_address(net_tun_device_t device);
net_address_t net_tun_device_ipv4_mask(net_tun_device_t device);
net_address_t net_tun_device_ipv6_address(net_tun_device_t device);

net_address_t net_tun_device_netif_ipv4_address(net_tun_device_t device);
net_address_t net_tun_device_netif_ipv6_address(net_tun_device_t device);

void net_tun_device_clear_all(net_tun_driver_t driver);

NET_END_DECL

#endif
