#include <assert.h>
#include "cpe/pal/pal_string.h"
#include "net_schedule.h"
#include "net_driver.h"
#include "net_ipset.h"
#include "net_timer.h"
#include "net_address.h"
#include "net_tun_driver_i.h"
#include "net_tun_device_i.h"
#include "net_tun_endpoint.h"
#include "net_tun_dgram.h"
#include "net_tun_acceptor_i.h"
#include "net_tun_utils.h"

static int net_tun_driver_init(net_driver_t driver);
static void net_tun_driver_fini(net_driver_t driver);
static int net_tun_driver_init_listener_ip4(net_tun_driver_t driver);
#if NET_TUN_USE_EV
static void net_tun_driver_tcp_timer_cb(EV_P_ ev_timer *watcher, int revents);
#endif

net_tun_driver_t
net_tun_driver_create(
    net_schedule_t schedule
#if NET_TUN_USE_EV
    , void * ev_loop
#endif
    )
{
    net_driver_t base_driver;

    base_driver = net_driver_create(
        schedule,
        "raw",
        /*driver*/
        sizeof(struct net_tun_driver),
        net_tun_driver_init,
        net_tun_driver_fini,
        /*timer*/
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        /*acceptor*/
        0,
        NULL,
        NULL,
        /*endpoint*/
        sizeof(struct net_tun_endpoint),
        net_tun_endpoint_init,
        net_tun_endpoint_fini,
        net_tun_endpoint_connect,
        net_tun_endpoint_close,
        net_tun_endpoint_on_output,
        /*dgram*/
        sizeof(struct net_tun_dgram),
        net_tun_dgram_init,
        net_tun_dgram_fini,
        net_tun_dgram_send);

    if (base_driver == NULL) return NULL;

    net_tun_driver_t driver = net_driver_data(base_driver);

#if NET_TUN_USE_EV
    driver->m_ev_loop = ev_loop;
    ev_timer_start(driver->m_ev_loop, &driver->m_tcp_timer);
#endif

    g_lwip_em = driver->m_em;
    lwip_init();
    
    return driver;
}

net_tun_driver_t net_tun_driver_cast(net_driver_t driver) {
    return strcmp(net_driver_name(driver), "raw") == 0 ? net_driver_data(driver) : NULL;
}

static int net_tun_driver_init(net_driver_t base_driver) {
    net_schedule_t schedule = net_driver_schedule(base_driver);
    net_tun_driver_t driver = net_driver_data(base_driver);

    driver->m_alloc = net_schedule_allocrator(schedule);
    driver->m_em = net_schedule_em(schedule);
#if NET_TUN_USE_EV
    driver->m_ev_loop = NULL;
#endif    
    driver->m_ipset = NULL;
    driver->m_listener_ip4 = NULL;
    driver->m_listener_ip6 = NULL;
    
    TAILQ_INIT(&driver->m_devices);
    driver->m_sock_process_fun = NULL;
    driver->m_sock_process_ctx = NULL;
    driver->m_data_monitor_fun = NULL;
    driver->m_data_monitor_ctx = NULL;
    driver->m_debug = 0;
    driver->m_default_device = NULL;

    if (cpe_hash_table_init(
            &driver->m_acceptors,
            driver->m_alloc,
            (cpe_hash_fun_t) net_tun_acceptor_hash,
            (cpe_hash_eq_t) net_tun_acceptor_eq,
            CPE_HASH_OBJ2ENTRY(net_tun_acceptor, m_hh),
            -1) != 0)
    {
        return -1;
    }

    if (net_tun_driver_init_listener_ip4(driver) != 0) {
        cpe_hash_table_fini(&driver->m_acceptors);
        return -1;
    }
    
#if NET_TUN_USE_EV
    double tcp_timer_interval = ((double)TCP_TMR_INTERVAL / 1000.0);
    ev_timer_init(&driver->m_tcp_timer, net_tun_driver_tcp_timer_cb, tcp_timer_interval, tcp_timer_interval);
#endif

#if NET_TUN_USE_DQ
    driver->m_tcp_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_retain(driver->m_tcp_timer);
    dispatch_source_set_event_handler(driver->m_tcp_timer, ^{ tcp_tmr(); });
    uint64_t tcp_timer_interval = ((uint64_t)TCP_TMR_INTERVAL) * 1000000u;
    dispatch_source_set_timer(
        driver->m_tcp_timer,
        dispatch_time(DISPATCH_TIME_NOW, tcp_timer_interval),
        tcp_timer_interval,
        0ULL);
    dispatch_resume(driver->m_tcp_timer);
#endif

    mem_buffer_init(&driver->m_data_buffer, driver->m_alloc);
    
    return 0;
}

static void net_tun_driver_fini(net_driver_t base_driver) {
    net_tun_driver_t driver = net_driver_data(base_driver);

#if NET_TUN_USE_EV
    ev_timer_stop(driver->m_ev_loop, &driver->m_tcp_timer);
#endif

#if NET_TUN_USE_DQ
    dispatch_source_set_event_handler(driver->m_tcp_timer, nil);
    dispatch_source_cancel(driver->m_tcp_timer);
    dispatch_release(driver->m_tcp_timer);
    driver->m_tcp_timer = nil;
#endif

    if (driver->m_listener_ip4) {
        tcp_close(driver->m_listener_ip4);
        driver->m_listener_ip4 = NULL;
    }

    if (driver->m_listener_ip6) {
        tcp_close(driver->m_listener_ip6);
        driver->m_listener_ip6 = NULL;
    }
    
    net_tun_acceptor_free_all(driver);
    cpe_hash_table_fini(&driver->m_acceptors);
                        
    while(!TAILQ_EMPTY(&driver->m_devices)) {
        net_tun_device_free(TAILQ_FIRST(&driver->m_devices));
    }

    if (driver->m_ipset) {
        net_ipset_free(driver->m_ipset);
    }

    mem_buffer_clear(&driver->m_data_buffer);
}

void net_tun_driver_free(net_tun_driver_t driver) {
    net_driver_free(net_driver_from_data(driver));
}

net_ipset_t net_tun_driver_ipset(net_tun_driver_t driver) {
    return driver->m_ipset;
}

net_ipset_t net_tun_driver_ipset_check_create(net_tun_driver_t driver) {
    if (driver->m_ipset == NULL) {
        driver->m_ipset = net_ipset_create(net_tun_driver_schedule(driver));
        if (driver->m_ipset == NULL) {
            CPE_ERROR(driver->m_em, "tun: driver create ipset fail!");
            return NULL;
        }
    }

    return driver->m_ipset;
}

uint8_t net_tun_driver_debug(net_tun_driver_t driver) {
    return driver->m_debug;
}

void net_tun_driver_set_debug(net_tun_driver_t driver, uint8_t debug) {
    driver->m_debug = debug;
}

void net_tun_driver_set_sock_create_processor(
    net_tun_driver_t driver,
    net_tun_driver_sock_create_process_fun_t process_fun,
    void * process_ctx)
{
    driver->m_sock_process_fun = process_fun;
    driver->m_sock_process_ctx = process_ctx;
}
    
void net_tun_driver_set_data_monitor(
    net_tun_driver_t driver,
    net_data_monitor_fun_t monitor_fun, void * monitor_ctx)
{
    driver->m_data_monitor_fun = monitor_fun;
    driver->m_data_monitor_ctx = monitor_ctx;
}

net_schedule_t net_tun_driver_schedule(net_tun_driver_t driver) {
    return net_driver_schedule(net_driver_from_data(driver));
}

mem_buffer_t net_tun_driver_tmp_buffer(net_tun_driver_t driver) {
    return net_schedule_tmp_buffer(net_driver_schedule(net_driver_from_data(driver)));
}

static err_t net_tun_driver_on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    net_tun_driver_t driver = arg;
    net_address_t local_addr = NULL;

    assert(err == ERR_OK);

    CPE_ERROR(driver->m_em, "xxxxx: netif_accept");
    uint8_t is_ipv6 = PCB_ISIPV6(newpcb) ? 1 : 0;

    struct tcp_pcb *this_listener = is_ipv6 ? driver->m_listener_ip6 : driver->m_listener_ip4;
    assert(this_listener);
    tcp_accepted(this_listener);

    local_addr = net_address_from_lwip(driver, is_ipv6, &newpcb->local_ip, newpcb->local_port);
    if (local_addr == NULL) {
        CPE_ERROR(driver->m_em, "tun: accept: create local address fail");
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    net_tun_acceptor_t acceptor = net_tun_acceptor_find(driver, local_addr);
    if (acceptor == NULL) {
        if (driver->m_debug) {
            CPE_INFO(driver->m_em, "tun: accept: no acceptor");
        }
        net_address_free(local_addr);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    if (net_tun_acceptor_on_accept(acceptor, newpcb, local_addr) != 0) {
        net_address_free(local_addr);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    net_address_free(local_addr);
    return ERR_OK;
}

static int net_tun_driver_init_listener_ip4(net_tun_driver_t driver) {
    struct tcp_pcb * l = tcp_new();
    if (l == NULL) {
        CPE_ERROR(driver->m_em, "tun: listener4: tcp_new failed");
        return -1;
    }

    ip_addr_t addr = ip_addr_any;
    if (tcp_bind(l, &addr, 0) != 0) {
        CPE_ERROR(driver->m_em, "tun: listener4: bind fail");
        return -1;
    }
            
    driver->m_listener_ip4 = tcp_listen_with_backlog(l, TCP_DEFAULT_LISTEN_BACKLOG);
    if (driver->m_listener_ip4 == NULL) {
        CPE_ERROR(driver->m_em, "tun: listener4: tcp_listen fail");
        tcp_close(l);
        return -1;
    }

    tcp_arg(driver->m_listener_ip4, driver);
    tcp_accept(driver->m_listener_ip4, net_tun_driver_on_accept);

    return 0;
}

#if NET_TUN_USE_EV

static void net_tun_driver_tcp_timer_cb(EV_P_ ev_timer *watcher, int revents) {
    tcp_tmr();
    return;
}

#endif
