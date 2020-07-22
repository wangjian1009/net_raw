#ifndef NET_TUN_DERICE_H_INCLEDED
#define NET_TUN_DERICE_H_INCLEDED
#include "net_tun_types.h"
#if NET_TUN_USE_DEV_NE
#import <NetworkExtension/NetworkExtension.h>
#endif

NET_BEGIN_DECL

#if NET_TUN_USE_DEV_TUN

typedef enum net_tun_device_init_type {
    net_tun_device_init_string,
#ifndef CPE_OS_WIN
    net_tun_device_init_fd,
#endif
} net_tun_device_init_type_t;

struct net_tun_device_init_data {
    net_tun_device_type_t m_dev_type;
    net_tun_device_init_type_t m_init_type;
    union {
        char *m_string;
        struct {
            int m_fd;
            int m_mtu;
        };
    } m_init_data;
};
#endif

#if NET_TUN_USE_DEV_NE
struct net_tun_device_init_data {
    NEPacketTunnelFlow * m_tunnelFlow;
    uint16_t m_mtu;
};
#endif

typedef struct net_tun_device_init_data * net_tun_device_init_data_t;

struct net_tun_device_netif_options {
    net_address_t m_ipv4_address;
    net_address_t m_ipv4_mask;
    net_address_t m_ipv6_address;
};
typedef struct net_tun_device_netif_options * net_tun_device_netif_options_t;

net_tun_device_t
net_tun_device_create(
    net_tun_driver_t driver
    , net_tun_device_init_data_t settings
    , net_tun_device_netif_options_t netif_settings);

void net_tun_device_free(net_tun_device_t device);

net_tun_device_t net_tun_device_default(net_tun_driver_t driver);

void net_tun_device_clear_all(net_tun_driver_t driver);

void net_tun_device_netif_options_clear(net_tun_device_netif_options_t netif_options);

NET_END_DECL

#endif
