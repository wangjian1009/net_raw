#ifndef NET_RAW_DEVICE_RAW_I_H_INCLEDED
#define NET_RAW_DEVICE_RAW_I_H_INCLEDED
#include "net_raw_device_i.h"

struct net_raw_device_raw {
    struct net_raw_device m_device;
    net_raw_device_raw_capture_list_t m_captures;
    int m_fd;
    struct ev_io m_watcher;
};

#endif
