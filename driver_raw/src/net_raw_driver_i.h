#ifndef NET_RAW_DRIVER_I_H_INCLEDED
#define NET_RAW_DRIVER_I_H_INCLEDED
#include "lwip/tcp_impl.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#undef mem_free
#undef mem_calloc
#include "cpe/pal/pal_queue.h"
#include "cpe/utils/memory.h"
#include "cpe/utils/error.h"
#include "cpe/utils/buffer.h"
#include "cpe/utils/hash.h"
#include "net_schedule.h"
#include "net_raw_driver.h"
#if NET_RAW_USE_EV
#include "ev.h"
#endif

typedef TAILQ_HEAD(net_raw_device_list, net_raw_device) net_raw_device_list_t;
typedef TAILQ_HEAD(net_raw_endpoint_list, net_raw_endpoint) net_raw_endpoint_list_t;
typedef TAILQ_HEAD(net_raw_device_raw_capture_list, net_raw_device_raw_capture) net_raw_device_raw_capture_list_t;
typedef TAILQ_HEAD(net_raw_device_listener_list, net_raw_device_listener) net_raw_device_listener_list_t;

typedef struct net_raw_device_type * net_raw_device_type_t;
typedef struct net_raw_endpoint * net_raw_endpoint_t;
typedef struct net_raw_dgram * net_raw_dgram_t;
typedef struct net_raw_timer * net_raw_timer_t;

struct net_raw_driver {
#if NET_RAW_USE_EV
    struct ev_loop * m_ev_loop;
#endif
    mem_allocrator_t m_alloc;
    error_monitor_t m_em;
    net_raw_driver_match_mode_t m_mode;
    net_ipset_t m_ipset;
    uint8_t m_debug;

#if NET_RAW_USE_EV
    struct ev_timer m_tcp_timer;
#else
    net_timer_t m_tcp_timer;
#endif
    struct mem_buffer m_data_buffer;

    net_raw_device_t m_default_device;
    net_raw_device_list_t m_devices;

    net_raw_device_raw_capture_list_t m_free_device_raw_captures;
    net_raw_device_listener_list_t m_free_device_listeners;

    net_raw_driver_sock_create_process_fun_t m_sock_process_fun;
    void * m_sock_process_ctx;
    net_data_monitor_fun_t m_data_monitor_fun;
    void * m_data_monitor_ctx;
};

mem_buffer_t net_raw_driver_tmp_buffer(net_raw_driver_t driver);
net_schedule_t net_raw_driver_schedule(net_raw_driver_t driver);

#endif
