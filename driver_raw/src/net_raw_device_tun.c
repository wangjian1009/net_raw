#include <assert.h>
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/utils/string_utils.h"
#include "net_address.h"
#include "net_raw_device_tun_i.h"
#include "net_raw_utils.h"

static int net_raw_device_tun_send(net_raw_device_t device, uint8_t *data, int data_len);
static void net_raw_device_tun_fini(net_raw_device_t device);

static struct net_raw_device_type s_device_type_tun = {
    "tun",
    net_raw_device_tun_send,
    net_raw_device_tun_fini,
};

net_raw_device_tun_t
net_raw_device_tun_create(
    net_raw_driver_t driver, const char * name
#if NET_RAW_USE_DEV_NE
    , void * tunnelFlow
#endif
    ) {
    net_raw_device_tun_t device_tun = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_tun));
    if (device_tun == NULL) {
        CPE_ERROR(driver->m_em, "raw: device alloc fail!");
        return NULL;
    }

    device_tun->m_address = NULL;
    device_tun->m_mask = NULL;
    
    uint16_t mtu = 0;

#if NET_RAW_USE_DEV_TUN
    if (net_raw_device_tun_init_dev(driver, device_tun, name, &mtu) != 0) {
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
#endif

#if NET_RAW_USE_DEV_NE
    if (net_raw_device_tun_init_dev(driver, device_tun, name, tunnelFlow, &mtu) != 0) {
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
#endif
    
    if (net_raw_device_init(
            &device_tun->m_device, driver, &s_device_type_tun,
            device_tun->m_address, device_tun->m_mask, mtu) != 0)
    {
        net_raw_device_tun_fini_dev(driver, device_tun);
        
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }

    if (driver->m_debug > 0) {
        char address[32];
        cpe_str_dup(address, sizeof(address), device_tun->m_address ? net_address_dump(net_raw_driver_tmp_buffer(driver), device_tun->m_address) : "");

        char mask[32];
        cpe_str_dup(mask, sizeof(mask), device_tun->m_mask ? net_address_dump(net_raw_driver_tmp_buffer(driver), device_tun->m_mask) : "");
        
        CPE_INFO(
            driver->m_em, "raw: %s: created: mtu=%d, address=%s, mask=%s",
            device_tun->m_dev_name, device_tun->m_device.m_frame_mtu, address, mask);
    }
    
    return device_tun;
}

net_raw_device_tun_t net_raw_device_tun_cast(net_raw_device_t device) {
    return device->m_type == &s_device_type_tun ? (net_raw_device_tun_t)device : NULL;    
}

static int net_raw_device_tun_send(net_raw_device_t device, uint8_t *data, int data_len) {
    net_raw_device_tun_t device_tun = (net_raw_device_tun_t)device;
    
    assert(data_len >= 0);
    assert(data_len <= device->m_frame_mtu);

#if NET_RAW_USE_DEV_TUN
    int bytes = write(device_tun->m_dev_fd, data, data_len);
    if (bytes < 0) {
        // malformed packets will cause errors, ignore them and act like
        // the packet was accepeted
    }
    else {
        if (bytes != data_len) {
            CPE_ERROR(device->m_driver->m_em, "%s: written %d expected %d", device->m_netif.name, bytes, data_len);
        }
    }
    return 0;
    
#elif NET_RAW_USE_DQ
    
    return 0;

#else
    CPE_ERROR(device->m_driver->m_em, "%s: send: device no backend support", device->m_netif.name);
    return -1;
#endif

}

static void net_raw_device_tun_fini(net_raw_device_t device) {
    net_raw_driver_t driver = device->m_driver;
    net_raw_device_tun_t device_tun = (net_raw_device_tun_t)device;

    net_raw_device_tun_fini_dev(driver, device_tun);

    if (device_tun->m_address) {
        net_address_free(device_tun->m_address);
        device_tun->m_address = NULL;
    }

    if (device_tun->m_mask) {
        net_address_free(device_tun->m_mask);
        device_tun->m_mask = NULL;
    }
}
