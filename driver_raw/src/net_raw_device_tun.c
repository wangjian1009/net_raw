#include <assert.h>
#include <errno.h>
#include <net/if.h>
#if CPE_OS_LINUX
#    include <linux/if_tun.h>
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_unistd.h"
#include "net_raw_device_tun_i.h"
#include "net_raw_utils.h"

static void net_raw_device_tun_rw_cb(EV_P_ ev_io *w, int revents);
static int net_raw_device_tun_send(net_raw_device_t device, uint8_t *data, int data_len);
static void net_raw_device_tun_fini(net_raw_device_t device);

static struct net_raw_device_type s_device_type_tun = {
    "tun",
    net_raw_device_tun_send,
    net_raw_device_tun_fini,
};

net_raw_device_tun_t
net_raw_device_tun_create(
    net_raw_driver_t driver, const char * name, net_address_t ip, net_address_t mask)
{
    net_raw_device_tun_t device_tun = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_tun));
    if (device_tun == NULL) {
        CPE_ERROR(driver->m_em, "raw: device alloc fail!");
        return NULL;
    }

    device_tun->m_dev_fd = -1;
    
    if (net_raw_device_init(&device_tun->m_device, driver, &s_device_type_tun, ip, mask) != 0) {
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
    
#if CPE_OS_LINUX

    if ((device_tun->m_dev_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: open fail, %d %s", name, errno, strerror(errno));
        net_raw_device_fini(&device_tun->m_device);
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
            
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

    if (ioctl(device_tun->m_dev_fd, TUNSETIFF, (void *) &ifr) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: ioctl fail, %d %s", name, errno, strerror(errno));
        close(device_tun->m_dev_fd);
        net_raw_device_fini(&device_tun->m_device);
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
    cpe_str_dup(device_tun->m_dev_name, sizeof(device_tun->m_dev_name), ifr.ifr_name);

    /*mtu*/
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: socket fail, %d %s", name, errno, strerror(errno));
        close(device_tun->m_dev_fd);
        net_raw_device_fini(&device_tun->m_device);
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
            
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, device_tun->m_dev_name);
    if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: get socket fail, %d %s", name, errno, strerror(errno));
        close(sock);
        close(device_tun->m_dev_fd);
        net_raw_device_fini(&device_tun->m_device);
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
            
    device_tun->m_device.m_frame_mtu = ifr.ifr_mtu;
    close(sock);

#endif /*CPE_OS_LINUX*/

    if (fcntl(device_tun->m_dev_fd, F_SETFL, O_NONBLOCK) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: set nonblock fail, %d %s", name, errno, strerror(errno));
        close(device_tun->m_dev_fd);
        net_raw_device_fini(&device_tun->m_device);
        mem_free(driver->m_alloc, device_tun);
        return NULL;
    }
    
    device_tun->m_watcher.data = device_tun;
    ev_io_init(&device_tun->m_watcher, net_raw_device_tun_rw_cb, device_tun->m_dev_fd, EV_READ);
    ev_io_start(driver->m_ev_loop, &device_tun->m_watcher);

    if (driver->m_debug > 0) {
        CPE_INFO(driver->m_em, "raw: device %s: created", name);
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
    
    int bytes = write(device_tun->m_dev_fd, data, data_len);
    if (bytes < 0) {
        // malformed packets will cause errors, ignore them and act like
        // the packet was accepeted
    }
    else {
        if (bytes != data_len) {
            CPE_ERROR(device->m_driver->m_em, "device %s: written %d expected %d", device->m_netif.name, bytes, data_len);
        }
    }

    return 0;
}

static void net_raw_device_tun_fini(net_raw_device_t device) {
    net_raw_driver_t driver = device->m_driver;
    net_raw_device_tun_t device_tun = (net_raw_device_tun_t)device;
    
    ev_io_stop(driver->m_ev_loop, &device_tun->m_watcher);
    close(device_tun->m_dev_fd);
}

static void net_raw_device_tun_rw_cb(EV_P_ ev_io *w, int revents) {
    net_raw_device_tun_t device_tun = w->data;
    net_raw_device_t device = &device_tun->m_device;
    net_raw_driver_t driver = device->m_driver;

    CPE_ERROR(driver->m_em, "xxxx rw_cb");
    
    if (revents & EV_READ) {
        mem_buffer_clear_data(&driver->m_data_buffer);
        void * data = mem_buffer_alloc(&driver->m_data_buffer, device->m_frame_mtu);
        if (data == NULL) {
            CPE_ERROR(
                driver->m_em, "device %s: rw: alloc data, size=%d fail",
                device->m_netif.name, device->m_frame_mtu);
            return;
        }
        
        do {
            int bytes = read(device_tun->m_dev_fd, data, device->m_frame_mtu);
            if (bytes <= 0) {
                if (bytes == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                else {
                    CPE_ERROR(
                        driver->m_em, "device %s: rw: read data error, errno=%d %s",
                        device->m_netif.name, errno, strerror(errno));
                    break;
                }
            }
    
            assert(bytes <= device->m_frame_mtu);

            if (bytes > UINT16_MAX) {
                CPE_ERROR(driver->m_em, "device %s: rw: packet too large", device->m_netif.name);
                break;
            }
            
            uint8_t * ethhead = NULL;
            uint8_t * iphead = data;  
            uint8_t * data = iphead + 20;

            CPE_INFO(
                driver->m_em, "device %s: rw: %s",
                device->m_netif.name,
                net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), ethhead, iphead, data));
            
            struct pbuf *p = pbuf_alloc(PBUF_RAW, bytes, PBUF_POOL);
            if (!p) {
                CPE_ERROR(driver->m_em, "device %s: rw: pbuf_alloc fail", device->m_netif.name);
                break;
            }

            err_t e = pbuf_take(p, data, bytes);
            if (e != ERR_OK) {
                CPE_ERROR(driver->m_em, "device %s: rw: pbuf_take fail", device->m_netif.name);
                pbuf_free(p);
                continue;
            }
            
            if (device->m_netif.input(p, &device->m_netif) != ERR_OK) {
                CPE_ERROR(driver->m_em, "device %s: rw: input fail", device->m_netif.name);
                pbuf_free(p);
                continue;
            }
        } while(1);
    }
}

