#ifndef NET_DRIVER_TURN_I_H_INCLEDED
#define NET_DRIVER_TURN_I_H_INCLEDED
#include "cpe/pal/pal_queue.h"
#include "cpe/utils/memory.h"
#include "cpe/utils/error.h"
#include "net_schedule.h"
#include "net_turn_driver.h"

typedef TAILQ_HEAD(net_turn_device_list, net_turn_device) net_turn_device_list_t;
typedef TAILQ_HEAD(net_turn_endpoint_list, net_turn_endpoint) net_turn_endpoint_list_t;

typedef struct net_turn_endpoint * net_turn_endpoint_t;
typedef struct net_turn_dgram * net_turn_dgram_t;
typedef struct net_turn_timer * net_turn_timer_t;

struct net_turn_driver {
    struct ev_loop * m_turn_loop;
    mem_allocrator_t m_alloc;
    error_monitor_t m_em;
    uint8_t m_debug;

    net_turn_device_list_t m_devices;
    
    net_turn_driver_sock_create_process_fun_t m_sock_process_fun;
    void * m_sock_process_ctx;
    net_data_monitor_fun_t m_data_monitor_fun;
    void * m_data_monitor_ctx;

};

#endif
