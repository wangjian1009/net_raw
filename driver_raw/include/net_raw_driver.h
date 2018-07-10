#ifndef NET_RAW_DRIVER_H_INCLEDED
#define NET_RAW_DRIVER_H_INCLEDED
#include "ev.h"
#include "cpe/utils/utils_types.h"
#include "net_raw_types.h"

NET_BEGIN_DECL

net_raw_driver_t net_raw_driver_create(
    net_schedule_t schedule, struct ev_loop * ev_loop, net_raw_driver_match_mode_t mode);

void net_raw_driver_free(net_raw_driver_t driver);

net_raw_driver_match_mode_t net_raw_driver_match_mode(net_raw_driver_t driver);
net_ipset_t net_raw_driver_ipset(net_raw_driver_t driver);

uint8_t net_raw_driver_debug(net_raw_driver_t driver);
void net_raw_driver_set_debug(net_raw_driver_t driver, uint8_t debug);

typedef int (*net_raw_driver_sock_create_process_fun_t)(
    net_raw_driver_t driver, void * ctx, int fd, net_address_t remote_addr);

void net_raw_driver_set_sock_create_processor(
    net_raw_driver_t driver,
    net_raw_driver_sock_create_process_fun_t process_fun, void * process_ctx);

void net_raw_driver_set_data_monitor(
    net_raw_driver_t driver,
    net_data_monitor_fun_t monitor_fun, void * monitor_ctx);

NET_END_DECL

#endif
