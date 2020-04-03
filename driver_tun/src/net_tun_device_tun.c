#include <assert.h>
#include <errno.h>
#if ! CPE_OS_WIN
#include <net/if.h>
#include <sys/ioctl.h>
#endif
#if CPE_OS_LINUX
#  include <linux/if_tun.h>
#endif
#include <fcntl.h>
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/utils/string_utils.h"
#include "net_address.h"
#include "net_watcher.h"
#include "net_tun_device_i.h"
#include "net_tun_utils.h"

#if NET_TUN_USE_DEV_TUN

static void net_tun_device_rw_cb(void * ctx, int fd, uint8_t do_read, uint8_t do_write);
static int net_tun_device_read_config(net_tun_device_t device);
static int net_tun_device_set_nonblock(net_tun_device_t device);
static int net_tun_device_start_rw(net_tun_device_t device);
static int net_tun_device_init_dev_by_fd(
    net_tun_driver_t driver, net_tun_device_t device, net_tun_device_init_data_t settings);
static int net_tun_device_init_dev_by_name(
    net_tun_driver_t driver, net_tun_device_t device, net_tun_device_init_data_t settings);

int net_tun_device_init_dev(
    net_tun_driver_t driver,
    net_tun_device_t device,
    net_tun_device_init_data_t settings)
{
    assert(settings->m_dev_type == net_tun_device_tun || settings->m_dev_type == net_tun_device_tap);

    switch(settings->m_init_type) {
    case net_tun_device_init_fd:
        if (net_tun_device_init_dev_by_fd(driver, device, settings) != 0) goto PROCESS_ERROR;
        break;
    case net_tun_device_init_string:
        if (net_tun_device_init_dev_by_name(driver, device, settings) != 0) goto PROCESS_ERROR;
        break;
    }

    if (net_tun_device_set_nonblock(device) != 0) goto PROCESS_ERROR;

    device->m_dev_input_packet = NULL;
    
    if (net_tun_device_start_rw(device) != 0) goto PROCESS_ERROR;

    return 0;

PROCESS_ERROR:
    if (device->m_dev_fd != -1) {
        if (device->m_dev_fd_close) {
            close(device->m_dev_fd);
        }
        device->m_dev_fd = -1;
    }
    device->m_dev_fd_close = 0;
    
    if (device->m_watcher) {
        net_watcher_free(device->m_watcher);
        device->m_watcher = NULL;
    }

    assert(device->m_dev_input_packet == NULL);
    
    return -1; 
}

int net_tun_device_init_dev_by_fd(
    net_tun_driver_t driver, net_tun_device_t device, net_tun_device_init_data_t settings)
{
    assert(settings->m_init_data.m_fd >= 0);
    assert(settings->m_init_data.m_mtu >= 0);
    assert(settings->m_dev_type != settings->m_dev_type == net_tun_device_tap
        || settings->m_init_data.m_mtu >= NET_TUN_ETHERNET_HEADER_LENGTH);

    device->m_dev_fd = settings->m_init_data.m_fd;
    device->m_mtu = settings->m_init_data.m_mtu;
    device->m_dev_fd_close = 0;
    snprintf(device->m_dev_name, sizeof(device->m_dev_name), "tun-fd-%d", device->m_dev_fd);

    return 0;
}

#if CPE_OS_LINUX

int net_tun_device_init_dev_by_name(net_tun_driver_t driver, net_tun_device_t device, net_tun_device_init_data_t settings) {
    device->m_dev_fd = -1;

    if ((device->m_dev_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        CPE_ERROR(
            driver->m_em, "tun: %s: open fail, %d %s",
            settings->m_init_data.m_dev_name, errno, strerror(errno));
        return -1;
    }
    device->m_dev_fd_close = 1;

    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags |= IFF_NO_PI;
    if (init_data.dev_type == net_tun_device_tun) {
        ifr.ifr_flags |= IFF_TUN;
    } else {
        ifr.ifr_flags |= IFF_TAP;
    }
    if (init_data.init.string) {
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", init_data.init.string);
    }

    if (ioctl(device->m_dev_fd, TUNSETIFF, (void *) &ifr) < 0) {
        CPE_ERROR(driver->m_em, "tun: %s: ioctl fail, %d %s", name, errno, strerror(errno));
        return -1;
    }
    cpe_str_dup(device->m_dev_name, sizeof(device->m_dev_name), ifr.ifr_name);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        CPE_ERROR(
            driver->m_em, "tun: %s: socket fail, %d %s",
            settings->m_init_data.m_dev_name, errno, strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    cpe_str_dup(ifr.ifr_name, sizeof(ifr.ifr_name), device->m_dev_name);

    /*mtu*/
    if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0) {
        CPE_ERROR(
            driver->m_em, "tun: %s: get mtu fail, %d %s",
            settings->m_init_data.m_dev_name, errno, strerror(errno));
        close(sock);
        return -1;
    }
    device->m_mtu = ifr.ifr_mtu;

    /* /\*address*\/ */
    /* if (ioctl(sock, SIOCGIFADDR, (void *)&ifr) < 0) { */
    /*     CPE_ERROR( */
    /*         driver->m_em, "tun: %s: get addr fail, %d %s", */
    /*         settings->m_init_data.m_dev_name, errno, strerror(errno)); */
    /*     close(sock); */
    /*     return -1; */
    /* } */
    /* device->m_ipv4_address = net_address_create_from_sockaddr( */
    /*     net_tun_driver_schedule(driver), (struct sockaddr *)(&ifr.ifr_addr), sizeof(ifr.ifr_addr)); */

    /* /\*mask*\/ */
    /* if (ioctl(sock, SIOCGIFNETMASK, (void *)&ifr) < 0) { */
    /*     CPE_ERROR( */
    /*         driver->m_em, "tun: %s: get mask fail, %d %s", */
    /*         settings->m_init_data.m_dev_name, errno, strerror(errno)); */
    /*     close(sock); */
    /*     return -1; */
    /* } */
    /* device->m_ipv4_mask = net_address_create_from_sockaddr( */
    /*     net_tun_driver_schedule(driver), (struct sockaddr *)(&ifr.ifr_netmask), sizeof(ifr.ifr_netmask)); */
    
    close(sock);

    return 0;
}
    
#else

int net_tun_device_init_dev_by_name(
    net_tun_driver_t driver, net_tun_device_t device, net_tun_device_init_data_t settings)
{
    CPE_ERROR(
        device->m_driver->m_em, "tun: %s: not support get device info",
        settings->m_init_data.m_string, errno, strerror(errno));
    return -1;
}

#endif

void net_tun_device_fini_dev(net_tun_driver_t driver, net_tun_device_t device) {
    if (device->m_watcher) {
        net_watcher_free(device->m_watcher);
        device->m_watcher = NULL;
    }

    if (device->m_dev_fd != -1) {
        if (device->m_dev_fd_close) {
            close(device->m_dev_fd);
        }
        device->m_dev_fd = -1;
    }
    device->m_dev_fd_close = 0;

    if (device->m_dev_input_packet) {
        mem_free(driver->m_alloc, device->m_dev_input_packet);
        device->m_dev_input_packet = NULL;
    }
}

int net_tun_device_packet_write(net_tun_device_t device, uint8_t *data, int data_len) {
    assert(data_len >= 0);
    assert(data_len <= device->m_mtu);

    int bytes = (int)write(device->m_dev_fd, data, data_len);
    if (bytes < 0) {
        // malformed packets will cause errors, ignore them and act like
        // the packet was accepeted
        CPE_ERROR(
            device->m_driver->m_em, "tun: %s: written fail, errno=%d (%s)",
            device->m_dev_name, errno, strerror(errno));
    }
    else {
        if (bytes != data_len) {
            CPE_ERROR(device->m_driver->m_em, "tun: %s: written %d expected %d", device->m_dev_name, bytes, data_len);
        }
    }
    return 0;
}

static void net_tun_device_rw_cb(void * ctx, int fd, uint8_t do_read, uint8_t do_write) {
    net_tun_device_t device = ctx;
    net_tun_driver_t driver = device->m_driver;
    
    if (do_read) {
        mem_buffer_clear_data(&driver->m_data_buffer);
        void * data = mem_buffer_alloc(&driver->m_data_buffer, device->m_mtu);
        if (data == NULL) {
            CPE_ERROR(
                driver->m_em, "tun: %s: rw: alloc data, size=%d fail",
                device->m_dev_name, device->m_mtu);
            return;
        }
        
        do {
            int bytes = (int)read(device->m_dev_fd, data, device->m_mtu);
            if (bytes <= 0) {
                if (bytes == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                else {
                    CPE_ERROR(
                        driver->m_em, "tun: %s: rw: read data error, errno=%d %s",
                        device->m_dev_name, errno, strerror(errno));
                    break;
                }
            }
    
            assert(bytes <= device->m_mtu);

            net_tun_device_packet_input(driver, device, data, (uint16_t)bytes);
        } while(1);
    }
}

static int net_tun_device_set_nonblock(net_tun_device_t device) {
#ifdef _MSC_VER
    u_long flag;
    flag = 1;
    if (ioctlsocket(_get_osfhandle(device->m_dev_fd), FIONBIO, &flag) != 0) {
        CPE_ERROR(device->m_driver->m_em, "tun: %s: set nonblock fail", device->m_dev_name);
        return -1;
    }
#else
    if (fcntl(device->m_dev_fd, F_SETFL, O_NONBLOCK) < 0) {
        CPE_ERROR(device->m_driver->m_em, "tun: %s: set nonblock fail, %d %s", device->m_dev_name, errno, strerror(errno));
        return -1;
    }
#endif
    return 0;
}

static int net_tun_device_start_rw(net_tun_device_t device) {
    net_tun_driver_t driver = device->m_driver;
    
    device->m_watcher = net_watcher_create(
        device->m_driver->m_inner_driver, device->m_dev_fd, device, net_tun_device_rw_cb);
    if (device->m_watcher == NULL) {
        CPE_ERROR(device->m_driver->m_em, "tun: %s: create watcher fail", device->m_dev_name);
        return -1;
    }

    net_watcher_update_read(device->m_watcher, 1);
    return 0;
}

#endif
