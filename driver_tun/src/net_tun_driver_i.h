#ifndef NET_TUN_DRIVER_I_H_INCLEDED
#define NET_TUN_DRIVER_I_H_INCLEDED
#include "lwip/priv/tcp_priv.h"
#undef mem_free
#undef mem_calloc
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "cpe/pal/pal_queue.h"
#include "cpe/utils/memory.h"
#include "cpe/utils/error.h"
#include "cpe/utils/buffer.h"
#include "cpe/utils/hash.h"
#include "net_schedule.h"
#include "net_tun_driver.h"
#if NET_TUN_USE_DQ
#include <dispatch/source.h>
#endif

typedef TAILQ_HEAD(net_tun_device_list, net_tun_device) net_tun_device_list_t;
typedef TAILQ_HEAD(net_tun_wildcard_acceptor_list, net_tun_wildcard_acceptor) net_tun_wildcard_acceptor_list_t;

typedef struct net_tun_acceptor * net_tun_acceptor_t;
typedef struct net_tun_endpoint * net_tun_endpoint_t;
typedef struct net_tun_dgram * net_tun_dgram_t;

struct net_tun_driver {
    mem_allocrator_t m_alloc;
    error_monitor_t m_em;

#if NET_TUN_USE_DRIVER
    net_driver_t m_inner_driver;
#endif
    
#if NET_TUN_USE_DRIVER
    net_timer_t m_tcp_timer;
#endif
    
#if NET_TUN_USE_DQ
    __unsafe_unretained dispatch_source_t m_tcp_timer;    
#endif

    uint8_t m_tcp_timer_counter;

    struct mem_buffer m_data_buffer;

    net_tun_device_t m_default_device;
    net_tun_device_list_t m_devices;

    net_tun_wildcard_acceptor_list_t m_wildcard_acceptors;
    struct cpe_hash_table m_acceptors;
    
    net_tun_driver_sock_create_process_fun_t m_sock_process_fun;
    void * m_sock_process_ctx;
    net_data_monitor_fun_t m_data_monitor_fun;
    void * m_data_monitor_ctx;
};

mem_buffer_t net_tun_driver_tmp_buffer(net_tun_driver_t driver);
net_schedule_t net_tun_driver_schedule(net_tun_driver_t driver);
void net_tun_dirver_do_timer(net_tun_driver_t driver);

#endif
