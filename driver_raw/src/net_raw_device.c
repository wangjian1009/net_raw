#include "assert.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/pal/pal_stdio.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "net_raw_device_i.h"

static int net_raw_device_init_netif(net_raw_device_t device, net_address_t ip, net_address_t mask);
static int net_raw_device_init_listener_ip4(net_raw_device_t device);

static err_t net_raw_device_netif_init(struct netif *netif);
static err_t net_raw_device_netif_input(struct pbuf *p, struct netif *inp);
static err_t net_raw_device_netif_output_ip4(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr);
static err_t net_raw_device_netif_output_ip6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr);

static err_t net_raw_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

int net_raw_device_init(
    net_raw_device_t device, net_raw_driver_t driver, net_raw_device_type_t type, 
    net_address_t ip, net_address_t mask)
{
    device->m_driver = driver;
    device->m_type = type;
    device->m_frame_mtu = 0;
    device->m_listener_ip4 = NULL;
    device->m_listener_ip6 = NULL;
    device->m_quitting = 0;

    if (net_raw_device_init_netif(device, ip, mask) != 0) return -1;

    if (net_raw_device_init_listener_ip4(device) != 0) {
        netif_remove(&device->m_netif);
        return -1;
    }

    if (driver->m_default_device == NULL) {
        driver->m_default_device = device;
        netif_set_default(&device->m_netif);
    }
    TAILQ_INSERT_TAIL(&driver->m_devices, device, m_next_for_driver);
    
    return 0;
}

void net_raw_device_fini(net_raw_device_t device) {
    net_raw_driver_t driver = device->m_driver;

    device->m_quitting = 1;
    
    if (device->m_listener_ip4) {
        tcp_close(device->m_listener_ip4);
        device->m_listener_ip4 = NULL;
    }

    if (device->m_listener_ip6) {
        tcp_close(device->m_listener_ip6);
        device->m_listener_ip6 = NULL;
    }
    
    netif_remove(&device->m_netif);

    if (driver->m_default_device == device) {
        driver->m_default_device = TAILQ_NEXT(device, m_next_for_driver);
    }
    
    TAILQ_REMOVE(&driver->m_devices, device, m_next_for_driver);

    if (driver->m_default_device == NULL) {
        driver->m_default_device = TAILQ_FIRST(&driver->m_devices);
    }

    if (driver->m_default_device) {
        netif_set_default(&driver->m_default_device->m_netif);
    }
}

void net_raw_device_free(net_raw_device_t device) {
    device->m_type->fini(device);
    net_raw_device_fini(device);
    mem_free(device->m_driver->m_alloc, device);
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
        CPE_ERROR(device->m_driver->m_em, "device: add netif fail!");
        return -1;
    }

    netif_set_up(&device->m_netif);

    // set netif pretend TCP
    netif_set_pretend_tcp(&device->m_netif, 1);

    return 0;
}

static int net_raw_device_init_listener_ip4(net_raw_device_t device) {
    struct tcp_pcb * l = tcp_new();
    if (l == NULL) {
        CPE_ERROR(device->m_driver->m_em, "device %s: init listener 4: tcp_new failed", device->m_netif.name);
        return -1;
    }

    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
        CPE_ERROR(device->m_driver->m_em, "device %s: init listener 4: bind_to_netif fail", device->m_netif.name);
        tcp_close(l);
        return -1;
    }

    device->m_listener_ip4 = tcp_listen(l);
    if (device->m_listener_ip4 == NULL) {
        CPE_ERROR(device->m_driver->m_em, "device %s: init listener 4: tcp_listen fail", device->m_netif.name);
        tcp_close(l);
        return -1;
    }

    tcp_accept(device->m_listener_ip4, net_raw_device_netif_accept);

    return 0;
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
    
    CPE_INFO(device->m_driver->m_em, "device %s: send packet", device->m_netif.name);

    if (device->m_quitting) {
        return ERR_OK;
    }

    if (!p->next) {
        if (p->len > device->m_frame_mtu) {
            CPE_ERROR(device->m_driver->m_em, "device %s: netif func output: no space left", device->m_netif.name);
            goto out;
        }

        device->m_type->send(device, (uint8_t *)p->payload, p->len);
    }
    else {
        void * device_write_buf = mem_buffer_alloc(net_raw_driver_tmp_buffer(device->m_driver), device->m_frame_mtu);
        int len = 0;
        do {
            if (p->len > device->m_frame_mtu - len) {
                CPE_ERROR(device->m_driver->m_em, "device %s: netif func output: no space left", device->m_netif.name);
                goto out;
            }
            memcpy(device_write_buf + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next));

        device->m_type->send(device, device_write_buf, len);
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
