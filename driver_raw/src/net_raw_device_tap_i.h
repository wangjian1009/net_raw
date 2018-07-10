#ifndef NET_RAW_DEVICE_TAP_I_H_INCLEDED
#define NET_RAW_DEVICE_TAP_I_H_INCLEDED
#include "net_raw_device.h"
#include "net_raw_driver_i.h"

struct net_raw_device_tap {
    int m_fd;
    int m_frame_mtu;
};

int net_raw_device_send(net_raw_device_t device, uint8_t *data, int data_len);

#endif
