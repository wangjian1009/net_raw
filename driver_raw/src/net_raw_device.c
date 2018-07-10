#include "assert.h"
#include <errno.h>
#include <net/if.h>
#if CPE_OS_LINUX
#    include <linux/if_tun.h>
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include "cpe/pal/pal_unistd.h"
#include "cpe/pal/pal_stdio.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "net_raw_device_i.h"

static void net_raw_device_rw_cb(EV_P_ ev_io *w, int revents);

static int net_raw_device_init_netif(net_raw_device_t device, net_address_t ip, net_address_t mask);
static int net_raw_device_init_listener_ip4(net_raw_device_t device);

static err_t net_raw_device_netif_init(struct netif *netif);
static err_t net_raw_device_netif_input(struct pbuf *p, struct netif *inp);
static err_t net_raw_device_netif_output_ip4(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr);
static err_t net_raw_device_netif_output_ip6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr);

static err_t net_raw_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

net_raw_device_t
net_raw_device_create(net_raw_driver_t driver, const char * name, net_address_t ip, net_address_t mask) {
    net_raw_device_t device = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device));
    if (device == NULL) {
        CPE_ERROR(driver->m_em, "raw: device alloc fail!");
        return NULL;
    }

    device->m_driver = driver;
    device->m_fd = -1;
    device->m_frame_mtu = 0;
    device->m_listener_ip4 = NULL;
    device->m_listener_ip6 = NULL;

    device->m_quitting = 0;
    
#if CPE_OS_LINUX

    if ((device->m_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: open fail, %d %s", name, errno, strerror(errno));
        mem_free(driver->m_alloc, device);
        return NULL;
    }
            
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

    if (ioctl(device->m_fd, TUNSETIFF, (void *) &ifr) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: ioctl fail, %d %s", name, errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
    cpe_str_dup(device->m_name, sizeof(device->m_name), ifr.ifr_name);

    /*mtu*/
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: socket fail, %d %s", name, errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
            
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, device->m_name);
    if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: get socket fail, %d %s", name, errno, strerror(errno));
        close(sock);
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
            
    device->m_frame_mtu = ifr.ifr_mtu;
    close(sock);

    if (fcntl(device->m_fd, F_SETFL, O_NONBLOCK) < 0) {
        CPE_ERROR(driver->m_em, "raw: device %s: set nonblock fail, %d %s", name, errno, strerror(errno));
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }

#endif /*CPE_OS_LINUX*/

    /*net device*/
    if (net_raw_device_init_netif(device, ip, mask) != 0) {
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }

    if (net_raw_device_init_listener_ip4(device) != 0) {
        netif_remove(&device->m_netif);
        close(device->m_fd);
        mem_free(driver->m_alloc, device);
        return NULL;
    }
    
    device->m_watcher.data = device;
    ev_io_init(&device->m_watcher, net_raw_device_rw_cb, device->m_fd, EV_READ);
    ev_io_start(driver->m_ev_loop, &device->m_watcher);

    if (driver->m_debug) {
        CPE_INFO(driver->m_em, "raw: device %s: created, name=%s", name, device->m_name);
    }
    
    TAILQ_INSERT_TAIL(&driver->m_devices, device, m_next_for_driver);
    
    return device;
}

void net_raw_device_free(net_raw_device_t device) {
    net_raw_driver_t driver = device->m_driver;

    if (device->m_listener_ip4) {
        tcp_close(device->m_listener_ip4);
        device->m_listener_ip4 = NULL;
    }

    if (device->m_listener_ip6) {
        tcp_close(device->m_listener_ip6);
        device->m_listener_ip6 = NULL;
    }
    
    netif_remove(&device->m_netif);

    close(device->m_fd);

    TAILQ_REMOVE(&driver->m_devices, device, m_next_for_driver);
    
    mem_free(driver->m_alloc, device);
}

static int net_raw_device_init_netif(net_raw_device_t device, net_address_t ip, net_address_t mask) {
    // make addresses for netif
    ip_addr_t addr;
    //addr.addr = netif_ipaddr.ipv4;
    ip_addr_t netmask;
    //netmask.addr = netif_netmask.ipv4;
    ip_addr_t gw;
    ip_addr_set_any(&gw);

    if (!netif_add(&device->m_netif, &addr, &netmask, &gw, device, net_raw_device_netif_init, net_raw_device_netif_input)) {
        CPE_ERROR(device->m_driver->m_em, "device %s: add netif fail!", device->m_name);
        return -1;
    }

    netif_set_up(&device->m_netif);

    // set netif pretend TCP
    netif_set_pretend_tcp(&device->m_netif, 1);

    // set netif default
    netif_set_default(&device->m_netif);

    return 0;
}

static int net_raw_device_init_listener_ip4(net_raw_device_t device) {
    struct tcp_pcb * l = tcp_new();
    if (l == NULL) {
        CPE_ERROR(device->m_driver->m_em, "device %s: init listener 4: tcp_new failed", device->m_name);
        return -1;
    }

    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
        CPE_ERROR(device->m_driver->m_em, "device %s: init listener 4: bind_to_netif fail", device->m_name);
        tcp_close(l);
        return -1;
    }

    device->m_listener_ip4 = tcp_listen(l);
    if (device->m_listener_ip4 == NULL) {
        CPE_ERROR(device->m_driver->m_em, "device %s: init listener 4: tcp_listen fail", device->m_name);
        tcp_close(l);
        return -1;
    }

    tcp_accept(device->m_listener_ip4, net_raw_device_netif_accept);

    return 0;
}

int net_raw_device_send(net_raw_device_t device, uint8_t *data, int data_len) {
    assert(data_len >= 0);
    assert(data_len <= device->m_frame_mtu);
    
    int bytes = write(device->m_fd, data, data_len);
    if (bytes < 0) {
        // malformed packets will cause errors, ignore them and act like
        // the packet was accepeted
    }
    else {
        if (bytes != data_len) {
            CPE_ERROR(device->m_driver->m_em, "device %s: written %d expected %d", device->m_name, bytes, data_len);
        }
    }

    return 0;
}

static void net_raw_device_rw_cb(EV_P_ ev_io *w, int revents) {
    /* if (revents & EV_READ) { */
        
    /* } */
}

static err_t net_raw_device_netif_init(struct netif *netif) {
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = net_raw_device_netif_output_ip4;
    netif->output_ip6 = net_raw_device_netif_output_ip6;

    return ERR_OK;
}

static err_t net_raw_device_netif_do_output(struct netif *netif, struct pbuf *p) {
    net_raw_device_t device = netif->state;
    
    CPE_INFO(device->m_driver->m_em, "device %s: send packet", device->m_name);

    if (device->m_quitting) {
        return ERR_OK;
    }

    if (!p->next) {
        if (p->len > device->m_frame_mtu) {
            CPE_ERROR(device->m_driver->m_em, "device %s: netif func output: no space left", device->m_name);
            goto out;
        }

        net_raw_device_send(device, (uint8_t *)p->payload, p->len);
    }
    else {
        void * device_write_buf = mem_buffer_alloc(net_raw_driver_tmp_buffer(device->m_driver), device->m_frame_mtu);
        int len = 0;
        do {
            if (p->len > device->m_frame_mtu - len) {
                CPE_ERROR(device->m_driver->m_em, "device %s: netif func output: no space left", device->m_name);
                goto out;
            }
            memcpy(device_write_buf + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next));

        net_raw_device_send(device, device_write_buf, len);
    }

out:
    return ERR_OK;
}

static err_t net_raw_device_netif_output_ip4(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
    return net_raw_device_netif_do_output(netif, p);
}

static err_t net_raw_device_netif_output_ip6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr) {
    return net_raw_device_netif_do_output(netif, p);
}

static err_t net_raw_device_netif_input(struct pbuf *p, struct netif *inp) {
    uint8_t ip_version = 0;
    if (p->len > 0) {
        ip_version = (((uint8_t *)p->payload)[0] >> 4);
    }

    switch(ip_version) {
    case 4:
        return ip_input(p, inp);
    case 6:
        return ip6_input(p, inp);
    }

    pbuf_free(p);

    return ERR_OK;
}

static err_t net_raw_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    return ERR_OK;
}
