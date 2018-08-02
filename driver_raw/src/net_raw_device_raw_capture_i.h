#ifndef NET_RAW_DEVICE_RAW_CAPTURE_I_H_INCLEDED
#define NET_RAW_DEVICE_RAW_CAPTURE_I_H_INCLEDED
#include "net_raw_device_raw_capture.h"
#include "net_raw_device_raw_i.h"

struct net_raw_device_raw_capture {
    net_raw_device_raw_t m_device;
    TAILQ_ENTRY(net_raw_device_raw_capture) m_next;
    struct cpe_hash_entry m_hh_for_source;
    net_address_t m_source_address;
    struct cpe_hash_entry m_hh_for_target;
    net_address_t m_target_address;
    int m_fd;
#if NET_RAW_USE_EV
    struct ev_io m_watcher;
#endif    
#if NET_RAW_USE_DQ
    __unsafe_unretained dispatch_source_t m_source_r;
#endif    
};

void net_raw_device_raw_capture_real_free(net_raw_device_raw_capture_t raw_capture);

net_raw_device_raw_capture_t net_raw_device_raw_capture_find_by_source(net_raw_device_raw_t raw, net_address_t source);
net_raw_device_raw_capture_t net_raw_device_raw_capture_find_by_target(net_raw_device_raw_t raw, net_address_t target);

uint32_t net_raw_device_raw_source_hash(net_raw_device_raw_capture_t capture, void * user_data);
int net_raw_device_raw_source_eq(net_raw_device_raw_capture_t l, net_raw_device_raw_capture_t r, void * user_data);
uint32_t net_raw_device_raw_target_hash(net_raw_device_raw_capture_t capture, void * user_data);
int net_raw_device_raw_target_eq(net_raw_device_raw_capture_t l, net_raw_device_raw_capture_t r, void * user_data);

#endif
