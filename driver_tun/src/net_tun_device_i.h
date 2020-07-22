#ifndef NET_TUN_DEVICE_I_H_INCLEDED
#define NET_TUN_DEVICE_I_H_INCLEDED
#include "net_tun_device.h"
#include "net_tun_driver_i.h"

#define NET_TUN_ETHERNET_HEADER_LENGTH 14

#if NET_TUN_USE_DEV_NE
@interface NetTunDeviceBridger : NSObject {
    @public net_tun_device_t m_device;
}
@end
#endif

struct net_tun_device {
    net_tun_driver_t m_driver;
    TAILQ_ENTRY(net_tun_device) m_next_for_driver;
    struct netif m_netif;
    struct tcp_pcb * m_listener_ip4;
    struct tcp_pcb * m_listener_ip6;
    uint16_t m_mtu;
    uint8_t m_quitting;
    char m_dev_name[16];

    /*device write buf*/
    uint8_t * m_write_combine_buf;
    
    /*使用tun设备接口 */
#if NET_TUN_USE_DEV_TUN
    uint8_t m_dev_fd_close;
    int m_dev_fd;
    uint8_t * m_dev_input_packet;
    net_watcher_t m_watcher;
#endif

    /*使用NetworkExtention设备接口 */
#if NET_TUN_USE_DEV_NE
    __unsafe_unretained NetTunDeviceBridger * m_bridger;
    __unsafe_unretained NEPacketTunnelFlow * m_tunnelFlow;
    __unsafe_unretained NSMutableArray<NSData *> * m_packets;
    __unsafe_unretained NSMutableArray<NSNumber *> * m_versions;
#endif
};

int net_tun_device_init_dev(
    net_tun_driver_t driver,
    net_tun_device_t device,
    net_tun_device_init_data_t settings);

void net_tun_device_fini_dev(net_tun_driver_t driver, net_tun_device_t device);

int net_tun_device_packet_input(net_tun_driver_t driver, net_tun_device_t device, uint8_t const * data, uint16_t bytes);
int net_tun_device_packet_write(net_tun_device_t device, uint8_t *data, int data_len);

#endif
