#ifndef NET_RAW_DERICE_LISTENER_H_INCLEDED
#define NET_RAW_DERICE_LISTENER_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_listener_t
net_raw_device_listener_create(
    net_raw_device_t device, net_address_t address, net_protocol_t protocol,
    net_raw_device_on_accept_fun_t on_accept, void * on_accept_ctx);

void net_raw_device_listener_free(net_raw_device_listener_t listener);

net_raw_device_listener_t
net_raw_device_listener_find(net_raw_device_t device, net_address_t address);

net_raw_device_t
net_raw_device_listener_device(net_raw_device_listener_t listener);

NET_END_DECL

#endif
