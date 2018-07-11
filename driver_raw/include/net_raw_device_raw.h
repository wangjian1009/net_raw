#ifndef NET_RAW_DERICE_RAW_H_INCLEDED
#define NET_RAW_DERICE_RAW_H_INCLEDED
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_device_raw_t net_raw_device_raw_create(net_raw_driver_t driver, uint8_t capture_all);
net_raw_device_raw_t net_raw_device_raw_cast(net_raw_device_t device);

uint8_t net_raw_device_raw_capture_all(net_raw_device_raw_t device_raw);

NET_END_DECL

#endif
