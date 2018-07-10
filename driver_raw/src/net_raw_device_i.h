#ifndef NET_RAW_DEVICE_I_H_INCLEDED
#define NET_RAW_DEVICE_I_H_INCLEDED
#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"
#include "lwip/netif.h"
#undef mem_calloc
#undef mem_free
#include "net_raw_device.h"
#include "net_raw_driver_i.h"

struct net_raw_device {
    net_raw_driver_t m_driver;
    TAILQ_ENTRY(net_raw_device) m_next_for_driver;
    char m_name[32];
    int m_fd;
    int m_frame_mtu;
    struct netif m_netif;
    struct tcp_pcb * m_listener_ip4;
    struct tcp_pcb * m_listener_ip6;
    struct ev_io m_watcher;
    uint8_t m_quitting;
};

int net_raw_device_send(net_raw_device_t device, uint8_t *data, int data_len);

#endif
