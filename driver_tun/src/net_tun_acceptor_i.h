#ifndef NET_TUN_ACCEPTOR_I_H_INCLEDED
#define NET_TUN_ACCEPTOR_I_H_INCLEDED
#include "net_tun_device_i.h"

struct net_tun_acceptor {
    net_address_t m_address;
    union {
        struct cpe_hash_entry m_hh;
        TAILQ_ENTRY(net_tun_acceptor) m_next;
    };
};

net_tun_acceptor_t
net_tun_acceptor_find(net_tun_driver_t driver, net_address_t address);

void net_tun_acceptor_free_all(net_tun_driver_t driver);

uint32_t net_tun_acceptor_hash(net_tun_acceptor_t capture, void * user_data);
int net_tun_acceptor_eq(net_tun_acceptor_t l, net_tun_acceptor_t r, void * user_data);

#endif
