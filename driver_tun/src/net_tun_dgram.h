#ifndef NET_TUN_DGRAM_H_INCLEDED
#define NET_TUN_DGRAM_H_INCLEDED
#include "net_tun_driver_i.h"

struct net_tun_dgram {
    struct udp_pcb * m_pcb;
};

int net_tun_dgram_init(net_dgram_t base_dgram);
void net_tun_dgram_fini(net_dgram_t base_dgram);
int net_tun_dgram_send(net_dgram_t base_dgram, net_address_t target, void const * data, size_t data_len);

#endif
