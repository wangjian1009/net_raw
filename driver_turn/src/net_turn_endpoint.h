#ifndef NET_TURN_ENDPOINT_H_INCLEDED
#define NET_TURN_ENDPOINT_H_INCLEDED
#include "cpe/pal/pal_socket.h"
#include "net_turn_driver_i.h"

struct net_turn_endpoint {
    int dummy;
};

int net_turn_endpoint_init(net_endpoint_t base_endpoint);
void net_turn_endpoint_fini(net_endpoint_t base_endpoint);
int net_turn_endpoint_connect(net_endpoint_t base_endpoint);
void net_turn_endpoint_close(net_endpoint_t base_endpoint);
int net_turn_endpoint_on_output(net_endpoint_t base_endpoint);

#endif
