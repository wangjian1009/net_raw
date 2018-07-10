#ifndef NET_RAW_TYPES_H_INCLEDED
#define NET_RAW_TYPES_H_INCLEDED
#include "net_system.h"

NET_BEGIN_DECL

typedef enum net_raw_driver_match_mode {
    net_raw_driver_match_white,
    net_raw_driver_match_black,
} net_raw_driver_match_mode_t;

typedef struct net_raw_driver * net_raw_driver_t;
typedef struct net_raw_device * net_raw_device_t;
typedef struct net_raw_device_tun * net_raw_device_tun_t;
typedef struct net_raw_device_raw * net_raw_device_raw_t;

NET_END_DECL

#endif
