#include "net_schedule.h"
#include "net_driver.h"
#include "net_turn_driver_i.h"
#include "net_turn_device_i.h"
#include "net_turn_endpoint.h"
#include "net_turn_dgram.h"

static int net_turn_driver_init(net_driver_t driver);
static void net_turn_driver_fini(net_driver_t driver);
static void net_turn_driver_tcp_timer_cb(EV_P_ ev_timer *watcher, int revents);

net_turn_driver_t
net_turn_driver_create(net_schedule_t schedule, struct ev_loop * ev_loop) {
    net_driver_t base_driver;

    base_driver = net_driver_create(
        schedule,
        "turn",
        /*driver*/
        sizeof(struct net_turn_driver),
        net_turn_driver_init,
        net_turn_driver_fini,
        /*timer*/
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        /*endpoint*/
        sizeof(struct net_turn_endpoint),
        net_turn_endpoint_init,
        net_turn_endpoint_fini,
        net_turn_endpoint_connect,
        net_turn_endpoint_close,
        net_turn_endpoint_on_output,
        /*dgram*/
        sizeof(struct net_turn_dgram),
        net_turn_dgram_init,
        net_turn_dgram_fini,
        net_turn_dgram_send);

    if (base_driver == NULL) return NULL;

    net_turn_driver_t driver = net_driver_data(base_driver);
    driver->m_ev_loop = ev_loop;
    ev_timer_start(driver->m_ev_loop, &driver->m_tcp_timer);

    lwip_init();
    
    return net_driver_data(base_driver);
}

static int net_turn_driver_init(net_driver_t base_driver) {
    net_schedule_t schedule = net_driver_schedule(base_driver);
    net_turn_driver_t driver = net_driver_data(base_driver);

    driver->m_alloc = net_schedule_allocrator(schedule);
    driver->m_em = net_schedule_em(schedule);
    driver->m_ev_loop = NULL;
    TAILQ_INIT(&driver->m_devices);
    driver->m_sock_process_fun = NULL;
    driver->m_sock_process_ctx = NULL;
    driver->m_data_monitor_fun = NULL;
    driver->m_data_monitor_ctx = NULL;
    driver->m_debug = 0;

    double tcp_timer_interval = ((double)TCP_TMR_INTERVAL / 1000.0);
    ev_timer_init(&driver->m_tcp_timer, net_turn_driver_tcp_timer_cb, tcp_timer_interval, tcp_timer_interval);
    
    return 0;
}

static void net_turn_driver_fini(net_driver_t base_driver) {
    net_turn_driver_t driver = net_driver_data(base_driver);

    ev_timer_stop(driver->m_ev_loop, &driver->m_tcp_timer);
    
    while(!TAILQ_EMPTY(&driver->m_devices)) {
        net_turn_device_free(TAILQ_FIRST(&driver->m_devices));
    }
}

void net_turn_driver_free(net_turn_driver_t driver) {
    net_driver_free(net_driver_from_data(driver));
}

uint8_t net_turn_driver_debug(net_turn_driver_t driver) {
    return driver->m_debug;
}

void net_turn_driver_set_debug(net_turn_driver_t driver, uint8_t debug) {
    driver->m_debug = debug;
}

void net_turn_driver_set_sock_create_processor(
    net_turn_driver_t driver,
    net_turn_driver_sock_create_process_fun_t process_fun,
    void * process_ctx)
{
    driver->m_sock_process_fun = process_fun;
    driver->m_sock_process_ctx = process_ctx;
}
    
void net_turn_driver_set_data_monitor(
    net_turn_driver_t driver,
    net_data_monitor_fun_t monitor_fun, void * monitor_ctx)
{
    driver->m_data_monitor_fun = monitor_fun;
    driver->m_data_monitor_ctx = monitor_ctx;
}

mem_buffer_t net_turn_driver_tmp_buffer(net_turn_driver_t driver) {
    return net_schedule_tmp_buffer(net_driver_schedule(net_driver_from_data(driver)));
}

static void net_turn_driver_tcp_timer_cb(EV_P_ ev_timer *watcher, int revents) {
    tcp_tmr();
    return;
}
