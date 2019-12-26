#ifndef NET_TUN_ENDPOINT_H_INCLEDED
#define NET_TUN_ENDPOINT_H_INCLEDED
#include "net_tun_driver_i.h"

struct net_tun_endpoint {
    struct tcp_pcb * m_pcb;
};

int net_tun_endpoint_init(net_endpoint_t base_endpoint);
void net_tun_endpoint_fini(net_endpoint_t base_endpoint);
int net_tun_endpoint_connect(net_endpoint_t base_endpoint);
void net_tun_endpoint_close(net_endpoint_t base_endpoint);
int net_tun_endpoint_update(net_endpoint_t base_endpoint);

void net_tun_endpoint_set_pcb(struct net_tun_endpoint * endpoint, struct tcp_pcb * pcb);
    
#endif
