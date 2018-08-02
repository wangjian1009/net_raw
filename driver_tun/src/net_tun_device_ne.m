#include "net_tun_device_i.h"

int net_tun_device_init_dev(net_tun_driver_t driver, net_tun_device_t device, const char * name, NEPacketTunnelFlow * tunnelFlow) {
    if (tunnelFlow == NULL) {
        CPE_ERROR(driver->m_em, "%s: init dev: no tunnelFlow", name);
        return -1;
    }
    
    device->m_tunnelFlow = tunnelFlow;
    [device->m_tunnelFlow retain];

    return 0;
}

void net_tun_device_fini_dev(net_tun_driver_t driver, net_tun_device_t device_tun) {
    if (device_tun->m_tunnelFlow) {
        [device_tun->m_tunnelFlow release];
    }
}
