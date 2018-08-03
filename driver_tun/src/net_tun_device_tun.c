#include <assert.h>
#include <errno.h>
#include <net/if.h>
#if NET_TUN_USE_DEV_TUN
#  include <linux/if_tun.h>
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/utils/string_utils.h"
#include "net_address.h"
#include "net_tun_device_i.h"
#include "net_tun_utils.h"

#if NET_TUN_USE_DEV_TUN

static void net_tun_device_rw_cb(EV_P_ ev_io *w, int revents);

int net_tun_device_init_tun(net_tun_driver_t driver, net_tun_device_t device, const char * name, uint16_t * mtu) {
    device->m_dev_fd = -1;
    
#if CPE_OS_LINUX
    if ((device->m_dev_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: open fail, %d %s", name, errno, strerror(errno));
        goto create_error;
    }
            
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
                            
    if (ioctl(device->m_dev_fd, TUNSETIFF, (void *) &ifr) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: ioctl fail, %d %s", name, errno, strerror(errno));
        goto create_error;
    }
    cpe_str_dup(device->m_dev_name, sizeof(device->m_dev_name), ifr.ifr_name);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: socket fail, %d %s", device->m_dev_name, errno, strerror(errno));
        goto create_error;
    }
            
    bzero(&ifr, sizeof(ifr));
    cpe_str_dup(ifr.ifr_name, sizeof(ifr.ifr_name), device->m_dev_name);

    /*mtu*/
    if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: get mtu fail, %d %s", device->m_dev_name, errno, strerror(errno));
        close(sock);
        goto create_error;
    }
    *mtu = ifr.ifr_mtu;

    /*address*/
    if (ioctl(sock, SIOCGIFADDR, (void *)&ifr) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: get addr fail, %d %s", device->m_dev_name, errno, strerror(errno));
        close(sock);
        goto create_error;
    }
    device->m_address = net_address_create_from_sockaddr(net_tun_driver_schedule(driver), (struct sockaddr *)(&ifr.ifr_addr), sizeof(ifr.ifr_addr));

    /*mask*/
    if (ioctl(sock, SIOCGIFNETMASK, (void *)&ifr) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: get mask fail, %d %s", device->m_dev_name, errno, strerror(errno));
        close(sock);
        goto create_error;
    }
    device->m_mask = net_address_create_from_sockaddr(net_tun_driver_schedule(driver), (struct sockaddr *)(&ifr.ifr_netmask), sizeof(ifr.ifr_netmask));
    
    close(sock);

#endif /*CPE_OS_LINUX*/

    if (fcntl(device->m_dev_fd, F_SETFL, O_NONBLOCK) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: set nonblock fail, %d %s", name, errno, strerror(errno));
        goto create_error;
    }
    
    device->m_watcher.data = device;
    ev_io_init(&device->m_watcher, net_tun_device_rw_cb, device->m_dev_fd, EV_READ);
    ev_io_start(driver->m_ev_loop, &device->m_watcher);

    return 0;

create_error:
    if (device->m_dev_fd != -1) {
        close(device->m_dev_fd);
        device->m_dev_fd = -1;
    }

    return -1;
}

void net_tun_device_fini_dev(net_tun_driver_t driver, net_tun_device_t device) {
    ev_io_stop(driver->m_ev_loop, &device->m_watcher);
    close(device->m_dev_fd);
}

static void net_tun_device_rw_cb(EV_P_ ev_io *w, int revents) {
    net_tun_device_t device = w->data;
    net_tun_driver_t driver = device->m_driver;
    
    if (revents & EV_READ) {
        mem_buffer_clear_data(&driver->m_data_buffer);
        void * data = mem_buffer_alloc(&driver->m_data_buffer, device->m_mtu);
        if (data == NULL) {
            CPE_ERROR(
                driver->m_em, "%s: rw: alloc data, size=%d fail",
                device->m_netif.name, device->m_mtu);
            return;
        }
        
        do {
            int bytes = read(device->m_dev_fd, data, device->m_mtu);
            if (bytes <= 0) {
                if (bytes == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                else {
                    CPE_ERROR(
                        driver->m_em, "%s: rw: read data error, errno=%d %s",
                        device->m_netif.name, errno, strerror(errno));
                    break;
                }
            }
    
            assert(bytes <= device->m_mtu);

            net_tun_device_packet_input(driver, device, data, (uint16_t)bytes);
        } while(1);
    }
}
#endif
