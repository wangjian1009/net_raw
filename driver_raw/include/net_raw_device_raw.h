#ifndef NET_RAW_DERICE_RAW_H_INCLEDED
#define NET_RAW_DERICE_RAW_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_raw_t net_raw_device_raw_create(net_raw_driver_t driver);
net_raw_device_raw_t net_raw_device_raw_cast(net_raw_device_t device);

NET_END_DECL

#endif
