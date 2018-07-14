#ifndef NET_RAW_DEVICE_I_H_INCLEDED
#define NET_RAW_DEVICE_I_H_INCLEDED
#include "net_raw_device.h"
#include "net_raw_driver_i.h"

struct net_raw_device_type {
    char m_name[16];
    int (*send)(net_raw_device_t device, uint8_t *data, int data_len);
    void (*fini)(net_raw_device_t device);
};

struct net_raw_device {
    net_raw_driver_t m_driver;
    TAILQ_ENTRY(net_raw_device) m_next_for_driver;
    net_raw_device_type_t m_type;
    uint16_t m_frame_mtu;
    struct netif m_netif;
    struct tcp_pcb * m_listener_ip4;
    struct tcp_pcb * m_listener_ip6;
    uint8_t m_quitting;
    struct cpe_hash_table m_listeners;
};

int net_raw_device_init(
    net_raw_device_t device, net_raw_driver_t driver, net_raw_device_type_t type,
    net_address_t ip, net_address_t mask, uint16_t frame_mtu);
void net_raw_device_fini(net_raw_device_t device);

#endif
