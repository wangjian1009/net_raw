#include "net_raw_device_tun_i.h"

int net_raw_device_tun_init_dev(net_raw_driver_t driver, net_raw_device_tun_t device_tun, const char * name, void * tunnelFlow, uint16_t * mtu) {
    return 0;
}

void net_raw_device_tun_fini_dev(net_raw_driver_t driver, net_raw_device_tun_t device_tun) {
    if (device_tun->m_tunnelFlow) {
        [device_tun->m_tunnelFlow release];
    }
}
