#ifndef NET_TURN_DGRAM_H_INCLEDED
#define NET_TURN_DGRAM_H_INCLEDED
#include "cpe/pal/pal_socket.h"
#include "net_turn_driver_i.h"

struct net_turn_dgram {
    int dummy;
};

int net_turn_dgram_init(net_dgram_t base_dgram);
void net_turn_dgram_fini(net_dgram_t base_dgram);
int net_turn_dgram_send(net_dgram_t base_dgram, net_address_t target, void const * data, size_t data_len);

#endif
