#include <assert.h>
#include "cpe/pal/pal_stdio.h"
#include "cpe/utils/string_utils.h"
#include "net_address.h"
#include "net_tun_device_i.h"

static void net_tun_device_start_read(net_tun_device_t device);

int net_tun_device_init_dev(
    net_tun_driver_t driver, net_tun_device_t device, const char * name,
    NEPacketTunnelFlow * tunnelFlow,  NEPacketTunnelNetworkSettings * settings)
{
    net_schedule_t schedule = net_tun_driver_schedule(driver);
    
    assert(tunnelFlow);

    cpe_str_dup(device->m_dev_name, sizeof(device->m_dev_name), name);
    device->m_mtu = (uint16_t)settings.MTU;

    NEIPv4Settings * ipv4Settings = settings.IPv4Settings;
    if (ipv4Settings) {
        if (ipv4Settings.addresses.count == 0) {
            CPE_ERROR(driver->m_em, "%s: ipv4 no address configured!", device->m_dev_name);
            return -1;
        }

        if (ipv4Settings.addresses.count != ipv4Settings.subnetMasks.count) {
            CPE_ERROR(driver->m_em, "%s: ipv4 address and mask count mismatch!", device->m_dev_name);
            return -1;
        }
        
        const char * str_address = [ipv4Settings.addresses[0] UTF8String];
        device->m_address = net_address_create_ipv4(schedule, str_address, 0);
        if (device->m_address == NULL) {
            CPE_ERROR(driver->m_em, "%s: address %s format error!", device->m_dev_name, str_address);
            return -1;
        }

        const char * str_mask = [ipv4Settings.subnetMasks[0] UTF8String];
        device->m_mask = net_address_create_ipv4(schedule, str_mask, 0);
        if (device->m_mask == NULL) {
            CPE_ERROR(driver->m_em, "%s: mask %s format error!", device->m_dev_name, str_mask);
            return -1;
        }
    }

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
