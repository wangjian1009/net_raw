#include <errno.h>
#include <net/if.h> 
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "cpe/pal/pal_stdio.h"
#include "cpe/pal/pal_strings.h"
#include "net_turn_device_i.h"

net_turn_device_t
net_turn_device_create(net_turn_driver_t driver, const char * device_path) {
    net_turn_device_t device = mem_alloc(driver->m_alloc, sizeof(struct net_turn_device));
    if (device == NULL) {
        CPE_ERROR(driver->m_em, "turn: device alloc fail!");
        return NULL;
    }

    device->m_driver = driver;

    device->m_fd = open(device_path, O_RDWR);
    if (device->m_fd < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: open fail, %d %s", errno, strerror(errno));
        mem_free(driver->m_alloc, device);
        return NULL;
    }

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *        IFF_NO_PI - Do not provide packet information
     */
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(device->m_fd, TUNSETIFF, (void *) &ifr) < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: ioctl fail, %d %s", errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }

    if (driver->m_debug) {
        CPE_INFO(driver->m_em, "turn: device: %s for reading...", ifr.ifr_name);
    }
    
    TAILQ_INSERT_TAIL(&driver->m_devices, device, m_next_for_driver);
    
    return device;
}

void net_turn_device_free(net_turn_device_t device) {
    net_turn_driver_t driver = device->m_driver;
    
    close(device->m_fd);

    TAILQ_REMOVE(&driver->m_devices, device, m_next_for_driver);
    
    mem_free(driver->m_alloc, device);
}

