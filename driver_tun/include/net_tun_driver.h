#ifndef NET_TUN_DRIVER_H_INCLEDED
#define NET_TUN_DRIVER_H_INCLEDED
#include "cpe/utils/utils_types.h"
#include "net_tun_types.h"

NET_BEGIN_DECL

net_tun_driver_t net_tun_driver_create(
    net_schedule_t schedule
#if NET_TUN_USE_EV
    , void * ev_loop
#endif    
    );

net_tun_driver_t net_tun_driver_find(net_schedule_t schedule);

net_tun_driver_t net_tun_driver_cast(net_driver_t base_driver);
net_driver_t net_tun_driver_base_driver(net_tun_driver_t driver);

void net_tun_driver_free(net_tun_driver_t driver);

typedef int (*net_tun_driver_sock_create_process_fun_t)(
    net_tun_driver_t driver, void * ctx, int fd, net_address_t remote_addr);

void net_tun_driver_set_sock_create_processor(
    net_tun_driver_t driver,
    net_tun_driver_sock_create_process_fun_t process_fun, void * process_ctx);

void net_tun_driver_set_data_monitor(
    net_tun_driver_t driver,
    net_data_monitor_fun_t monitor_fun, void * monitor_ctx);

NET_END_DECL

#endif
