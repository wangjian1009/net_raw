#ifndef NET_TUN_TYPES_H_INCLEDED
#define NET_TUN_TYPES_H_INCLEDED
#include "net_system.h"

NET_BEGIN_DECL

typedef struct net_tun_driver * net_tun_driver_t;
typedef struct net_tun_device * net_tun_device_t;

#if ! NET_TUN_USE_DQ
#  define NET_TUN_USE_EV 1
#endif

#if ! NET_TUN_USE_DEV_NE
#  define NET_TUN_USE_DEV_TUN 1
#endif

NET_END_DECL

#endif
