#include "assert.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "net_timer.h"
#include "net_driver.h"
#include "net_turn_timer.h"

static void net_turn_timer_cb(EV_P_ ev_timer *watcher, int revents);

int net_turn_timer_init(net_timer_t base_timer) {
    net_turn_timer_t timer = net_timer_data(base_timer);

    bzero(&timer->m_watcher, sizeof(timer->m_watcher));
    timer->m_watcher.data = timer;
    return 0;
}

void net_turn_timer_fini(net_timer_t base_timer) {
    net_turn_timer_t timer = net_timer_data(base_timer);
    net_turn_driver_t driver = net_driver_data(net_timer_driver(base_timer));
    ev_timer_stop(driver->m_turn_loop, &timer->m_watcher);
}

void net_turn_timer_active(net_timer_t base_timer, uint32_t delay_ms) {
    net_turn_timer_t timer = net_timer_data(base_timer);
    net_turn_driver_t driver = net_driver_data(net_timer_driver(base_timer));

    ev_timer_stop(driver->m_turn_loop, &timer->m_watcher);
    ev_timer_init(&timer->m_watcher, net_turn_timer_cb, ((double)delay_ms / 1000.0), 0.0f);
    ev_timer_start(driver->m_turn_loop, &timer->m_watcher);
}

void net_turn_timer_cancel(net_timer_t base_timer) {
    net_turn_timer_t timer = net_timer_data(base_timer);
    if (!ev_is_active(&timer->m_watcher)) return;

    net_turn_driver_t driver = net_driver_data(net_timer_driver(base_timer));
    ev_timer_stop(driver->m_turn_loop, &timer->m_watcher);
}

uint8_t net_turn_timer_is_active(net_timer_t base_timer) {
    net_turn_timer_t timer = net_timer_data(base_timer);
    return ev_is_active(&timer->m_watcher);
}

static void net_turn_timer_cb(EV_P_ ev_timer *watcher, int revents) {
    net_turn_timer_t timer = watcher->data;
    net_timer_t base_timer = net_timer_from_data(timer);
    net_turn_driver_t driver = net_driver_data(net_timer_driver(base_timer));

    ev_timer_stop(driver->m_turn_loop, &timer->m_watcher);

    net_timer_process(base_timer);
}
