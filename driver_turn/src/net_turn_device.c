#include <errno.h>
#include <net/if.h> 
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "cpe/pal/pal_stdio.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "net_turn_device_i.h"

static void net_turn_device_rw_cb(EV_P_ ev_io *w, int revents);

net_turn_device_t
net_turn_device_create(net_turn_driver_t driver, const char * device_path) {
    net_turn_device_t device = mem_alloc(driver->m_alloc, sizeof(struct net_turn_device));
    if (device == NULL) {
        CPE_ERROR(driver->m_em, "turn: device alloc fail!");
        return NULL;
    }

    device->m_driver = driver;

    if ((device->m_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: open fail, %d %s", device_path, errno, strerror(errno));
        mem_free(driver->m_alloc, device);
        return NULL;
    }
            
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", device_path);

    if (ioctl(device->m_fd, TUNSETIFF, (void *) &ifr) < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: ioctl fail, %d %s", device_path, errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
    cpe_str_dup(device->m_name, sizeof(device->m_name), ifr.ifr_name);

    /*mtu*/
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: socket fail, %d %s", device_path, errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
            
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, device->m_name);
    if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: get socket fail, %d %s", device_path, errno, strerror(errno));
        close(sock);
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
            
    device->m_frame_mtu = ifr.ifr_mtu;
    close(sock);

    if (fcntl(device->m_fd, F_SETFL, O_NONBLOCK) < 0) {
        CPE_ERROR(driver->m_em, "turn: device %s: set nonblock fail, %d %s", device_path, errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }

    device->m_watcher.data = device;
    ev_io_init(&device->m_watcher, net_turn_device_rw_cb, device->m_fd, EV_READ);
    ev_io_start(driver->m_turn_loop, &device->m_watcher);
    
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

static void net_turn_device_rw_cb(EV_P_ ev_io *w, int revents) {
    
}
