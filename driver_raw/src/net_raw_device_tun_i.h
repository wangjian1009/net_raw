#ifndef NET_RAW_DEVICE_TUN_I_H_INCLEDED
#define NET_RAW_DEVICE_TUN_I_H_INCLEDED
#include "net_raw_device_tun.h"
#include "net_raw_device_i.h"

struct net_raw_device_tun {
    struct net_raw_device m_device;
    char m_dev_name[16];
    int m_dev_fd;
    struct ev_io m_watcher;
};

#endif
