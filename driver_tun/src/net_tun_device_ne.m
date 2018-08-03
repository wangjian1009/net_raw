#include <assert.h>
#include "cpe/pal/pal_stdio.h"
#include "cpe/utils/string_utils.h"
#include "net_tun_device_i.h"

static void net_tun_device_start_read(net_tun_device_t device);

int net_tun_device_init_dev(net_tun_driver_t driver, net_tun_device_t device, const char * name, NEPacketTunnelFlow * tunnelFlow, uint16_t mtu) {
    assert(tunnelFlow);

    cpe_str_dup(device->m_dev_name, sizeof(device->m_dev_name), name);
    device->m_mtu = mtu;

    device->m_tunnelFlow = tunnelFlow;
    [device->m_tunnelFlow retain];

    net_tun_device_start_read(device);
    
    return 0;
}

void net_tun_device_fini_dev(net_tun_driver_t driver, net_tun_device_t device) {
    if (device->m_tunnelFlow) {
        [device->m_tunnelFlow release];
    }
}

static void net_tun_device_start_read(net_tun_device_t device) {
    [device->m_tunnelFlow readPacketsWithCompletionHandler: ^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
            dispatch_async(
                dispatch_get_main_queue(),
                ^{
                    net_tun_driver_t driver = device->m_driver;
                    for(uint32_t i = 0; i < [packets count]; ++i) {
                        NSData * packet = packets[i];
                        uint64_t packet_count = [packet length];
                        if (packet_count > UINT16_MAX) {
                            CPE_ERROR(driver->m_em, "%s: packet input: packet " FMT_UINT64_T " overflow uint16", device->m_netif.name, packet_count);
                            continue;
                        }

                        net_tun_device_packet_input(driver, device, (uint8_t const *)[packet bytes], (uint16_t)packet_count);
                    }

                    net_tun_device_start_read(device);
                });
        }];
}
