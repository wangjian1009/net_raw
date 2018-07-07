#ifndef NET_TURN_DEVICE_I_H_INCLEDED
#define NET_TURN_DEVICE_I_H_INCLEDED
#include "net_turn_device.h"
#include "net_turn_driver_i.h"

struct net_turn_device {
    net_turn_driver_t m_driver;
    TAILQ_ENTRY(net_turn_device) m_next_for_driver;
    int m_fd;
    struct ev_io m_watcher;
};

#endif
