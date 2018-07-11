#ifndef NET_RAW_DERICE_RAW_CAPTURE_H_INCLEDED
#define NET_RAW_DERICE_RAW_CAPTURE_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_raw_capture_t
net_raw_device_raw_capture_create(
    net_raw_device_raw_t raw, net_address_t source, net_address_t target);

void net_raw_device_raw_capture_free(net_raw_device_raw_capture_t raw_capture);

NET_END_DECL

#endif
