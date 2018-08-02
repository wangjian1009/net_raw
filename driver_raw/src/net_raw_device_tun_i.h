#ifndef NET_RAW_DEVICE_TUN_I_H_INCLEDED
#define NET_RAW_DEVICE_TUN_I_H_INCLEDED
#include "net_raw_device_tun.h"
#include "net_raw_device_i.h"

struct net_raw_device_tun {
    struct net_raw_device m_device;
    char m_dev_name[16];
    net_address_t m_address;
    net_address_t m_mask;
    /*使用tun设备接口 */
#if NET_RAW_USE_DEV_TUN
    int m_dev_fd;
    struct ev_io m_watcher;
#endif

    /*使用NetworkExtention设备接口 */
#if NET_RAW_USE_DQ
    __unsafe_unretained dispatch_source_t m_source_r;
    __unsafe_unretained dispatch_source_t m_source_w;
#endif
};

#if NET_RAW_USE_DEV_TUN
int net_raw_device_tun_init_dev(net_raw_driver_t driver, net_raw_device_tun_t device_tun, const char * name, uint16_t * mtu);
#endif

void net_raw_device_tun_fini_dev(net_raw_driver_t driver, net_raw_device_tun_t device_tun);

#endif
