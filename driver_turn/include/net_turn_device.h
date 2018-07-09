#ifndef NET_TURN_DERICE_H_INCLEDED
#define NET_TURN_DERICE_H_INCLEDED
#include "net_turn_types.h"

NET_BEGIN_DECL

net_turn_device_t net_turn_device_create(net_turn_driver_t driver, const char * name);
void net_turn_device_free(net_turn_device_t device);

NET_END_DECL

#endif
