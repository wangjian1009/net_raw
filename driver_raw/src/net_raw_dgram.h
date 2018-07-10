#ifndef NET_RAW_DGRAM_H_INCLEDED
#define NET_RAW_DGRAM_H_INCLEDED
#include "cpe/pal/pal_socket.h"
#include "net_raw_driver_i.h"

struct net_raw_dgram {
    int dummy;
};

int net_raw_dgram_init(net_dgram_t base_dgram);
void net_raw_dgram_fini(net_dgram_t base_dgram);
int net_raw_dgram_send(net_dgram_t base_dgram, net_address_t target, void const * data, size_t data_len);

#endif
