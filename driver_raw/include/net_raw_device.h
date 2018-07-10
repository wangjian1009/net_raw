#ifndef NET_RAW_DERICE_H_INCLEDED
#define NET_RAW_DERICE_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

void net_raw_device_free(net_raw_device_t device);

const char * net_raw_device_name(net_raw_device_t device);

net_raw_device_t net_raw_device_default(net_raw_driver_t driver);

NET_END_DECL

#endif
