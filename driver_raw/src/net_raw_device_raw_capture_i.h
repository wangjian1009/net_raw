#ifndef NET_RAW_DEVICE_RAW_CAPTURE_I_H_INCLEDED
#define NET_RAW_DEVICE_RAW_CAPTURE_I_H_INCLEDED
#include "net_raw_device_raw_capture.h"
#include "net_raw_device_raw_i.h"

struct net_raw_device_raw_capture {
    net_raw_device_raw_t m_device;
    TAILQ_ENTRY(net_raw_device_raw_capture) m_next;
    int m_fd;
    struct ev_io m_watcher;
};

void net_raw_device_raw_capture_real_free(net_raw_device_raw_capture_t raw_capture);

#endif
