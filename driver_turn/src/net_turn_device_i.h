#ifndef NET_TURN_DEVICE_I_H_INCLEDED
#define NET_TURN_DEVICE_I_H_INCLEDED
#include "net_turn_device.h"
#include "net_turn_driver_i.h"

struct net_turn_device {
    net_turn_driver_t m_driver;
    TAILQ_ENTRY(net_turn_device) m_next_for_driver;
    char m_name[32];
    int m_fd;
    int m_frame_mtu;
    struct netif m_netif;
    struct ev_io m_watcher;
    uint8_t m_quitting;
};

int net_turn_device_send(net_turn_device_t device, uint8_t *data, int data_len);

#endif
