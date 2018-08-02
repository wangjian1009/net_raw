#include <assert.h>
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/utils/string_utils.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_tun_device_i.h"
#include "net_tun_utils.h"
#include "net_tun_acceptor_i.h"

static int net_tun_device_init_netif(net_tun_device_t device);
static int net_tun_device_init_listener_ip4(net_tun_device_t device);

static err_t net_tun_device_netif_init(struct netif *netif);
static err_t net_tun_device_netif_input(struct pbuf *p, struct netif *inp);
static err_t net_tun_device_netif_output_ip4(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr);
static err_t net_tun_device_netif_output_ip6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr);

static err_t net_tun_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err);
static int net_tun_device_send(net_tun_device_t device, uint8_t *data, int data_len);

net_tun_device_t
net_tun_device_create(
    net_tun_driver_t driver, const char * name
#if NET_TUN_USE_DEV_NE
    , void * tunnelFlow
#endif
    )
{
    net_tun_device_t device = mem_alloc(driver->m_alloc, sizeof(struct net_tun_device));
    if (device == NULL) {
        CPE_ERROR(driver->m_em, "raw: device alloc fail!");
        return NULL;
    }

    device->m_driver = NULL;
    device->m_address = NULL;
    device->m_mask = NULL;
    device->m_quitting = 0;
    device->m_mtu = 0;
    device->m_listener_ip4 = NULL;
    device->m_listener_ip6 = NULL;

#if NET_TUN_USE_DEV_TUN
    if (net_tun_device_init_dev(driver, device, name) != 0) {
        mem_free(driver->m_alloc, device);
        return NULL;
    }
#endif

#if NET_TUN_USE_DEV_NE
    if (net_tun_device_init_dev(driver, device, name, tunnelFlow) != 0) {
        mem_free(driver->m_alloc, device);
        return NULL;
    }
#endif

    uint8_t netif_init = 0;
    if (net_tun_device_init_netif(device) != 0) {
        goto create_errror;
    }
    netif_init = 1;
    
    if (net_tun_device_init_listener_ip4(device) != 0) {
        goto create_errror;
    }

    if (driver->m_default_device == NULL) {
        driver->m_default_device = device;
        netif_set_default(&device->m_netif);
    }
    TAILQ_INSERT_TAIL(&driver->m_devices, device, m_next_for_driver);
    
    if (driver->m_debug > 0) {
        char address[32];
        cpe_str_dup(address, sizeof(address), device->m_address ? net_address_dump(net_tun_driver_tmp_buffer(driver), device->m_address) : "");

        char mask[32];
        cpe_str_dup(mask, sizeof(mask), device->m_mask ? net_address_dump(net_tun_driver_tmp_buffer(driver), device->m_mask) : "");
        
        CPE_INFO(
            driver->m_em, "raw: %s: created: mtu=%d, address=%s, mask=%s",
            device->m_dev_name, device->m_mtu, address, mask);
    }
    
    return device;

create_errror:
    if (device->m_address) {
        net_address_free(device->m_address);
        device->m_address = NULL;
    }

    if (device->m_mask) {
        net_address_free(device->m_mask);
        device->m_mask = NULL;
    }
    
    if (device->m_listener_ip4) {
        tcp_close(device->m_listener_ip4);
        device->m_listener_ip4 = NULL;
    }

    if (device->m_listener_ip6) {
        tcp_close(device->m_listener_ip6);
        device->m_listener_ip6 = NULL;
    }

    if (netif_init) {
        netif_remove(&device->m_netif);
    }
    
    net_tun_device_fini_dev(driver, device);
    
    mem_free(driver->m_alloc, device);

    return NULL;
}

void net_tun_device_free(net_tun_device_t device) {
    net_tun_driver_t driver = device->m_driver;

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

    if (device->m_address) {
        net_address_free(device->m_address);
        device->m_address = NULL;
    }

    if (device->m_mask) {
        net_address_free(device->m_mask);
        device->m_mask = NULL;
    }

    mem_free(driver->m_alloc, device);
}

const char * net_tun_device_name(net_tun_device_t device) {
    return device->m_netif.name;
}

net_tun_device_t net_tun_device_default(net_tun_driver_t driver) {
    return driver->m_default_device;
}

net_address_t net_tun_driver_address(net_tun_device_t device) {
    return device->m_address;
}

net_address_t net_tun_driver_mask(net_tun_device_t device) {
    return device->m_mask;
}

net_address_t net_tun_device_gen_local_address(net_tun_device_t device) {
    if (device->m_address == NULL || device->m_mask == NULL) {
        CPE_ERROR(device->m_driver->m_em, "%s: gen local address: no ip or mask!", device->m_netif.name);
        return NULL;
    }

    return net_address_rand_same_network(device->m_address, device->m_mask);
}

static int net_tun_device_send(net_tun_device_t device, uint8_t *data, int data_len) {
    assert(data_len >= 0);
    assert(data_len <= device->m_mtu);

#if NET_TUN_USE_DEV_TUN
    int bytes = write(device->m_dev_fd, data, data_len);
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
    
#elif NET_TUN_USE_DQ
    
    return 0;

#else
    CPE_ERROR(device->m_driver->m_em, "%s: send: device no backend support", device->m_netif.name);
    return -1;
#endif

}

static int net_tun_device_init_netif(net_tun_device_t device) {
    // make addresses for netif
    ip_addr_t addr;
    if (device->m_address) {
        net_address_to_lwip_ipv4(&addr, device->m_address);
    }
    else {
        ip_addr_set_any(&addr);
    }
    
    ip_addr_t netmask;
    if (device->m_mask) {
        net_address_to_lwip_ipv4(&netmask, device->m_mask);
    }
    else {
        ip_addr_set_any(&netmask);
    }
    
    ip_addr_t gw;
    ip_addr_set_any(&gw);

    if (!netif_add(&device->m_netif, &addr, &netmask, &gw, device, net_tun_device_netif_init, net_tun_device_netif_input)) {
        CPE_ERROR(device->m_driver->m_em, "device: add netif fail!");
        return -1;
    }

    netif_set_up(&device->m_netif);

    // set netif pretend TCP
    netif_set_pretend_tcp(&device->m_netif, 1);

    return 0;
}

static int net_tun_device_init_listener_ip4(net_tun_device_t device) {
    struct tcp_pcb * l = tcp_new();
    if (l == NULL) {
        CPE_ERROR(device->m_driver->m_em, "%s: init listener 4: tcp_new failed", device->m_netif.name);
        return -1;
    }
        
    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
        CPE_ERROR(device->m_driver->m_em, "%s: init listener 4: bind_to_netif fail", device->m_netif.name);
        tcp_close(l);
        return -1;
    }

    device->m_listener_ip4 = tcp_listen(l);
    if (device->m_listener_ip4 == NULL) {
        CPE_ERROR(device->m_driver->m_em, "%s: init listener 4: tcp_listen fail", device->m_netif.name);
        tcp_close(l);
        return -1;
    }

    tcp_arg(device->m_listener_ip4, device);
    tcp_accept(device->m_listener_ip4, net_tun_device_netif_accept);

    return 0;
}

static err_t net_tun_device_netif_init(struct netif *netif) {
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = net_tun_device_netif_output_ip4;
    netif->output_ip6 = net_tun_device_netif_output_ip6;

    return ERR_OK;
}

static err_t net_tun_device_netif_do_output(struct netif *netif, struct pbuf *p) {
    net_tun_device_t device = netif->state;
    net_tun_driver_t driver = device->m_driver;

    if (device->m_quitting) {
        return ERR_OK;
    }

    if (!p->next) {
        if (p->len > device->m_mtu) {
            CPE_ERROR(
                driver->m_em, "%s: output: len %d overflow, mtu=%d",
                device->m_netif.name, p->len, device->m_mtu);
            goto out;
        }

        if (driver->m_debug >= 2) {
            CPE_INFO(
                device->m_driver->m_em,
                "%s: OUT: %d |      %s", device->m_netif.name, p->len,
                net_tun_dump_raw_data(net_tun_driver_tmp_buffer(driver), NULL, (uint8_t *)p->payload, NULL));
        }

        net_tun_device_send(device, (uint8_t *)p->payload, p->len);
    }
    else {
        void * device_write_buf = mem_buffer_alloc(net_tun_driver_tmp_buffer(device->m_driver), device->m_mtu);
        int len = 0;
        do {
            if (p->len > device->m_mtu - len) {
                CPE_ERROR(
                    device->m_driver->m_em, "%s: output: len %d overflow, mtu=%d",
                    device->m_netif.name, p->len + len, device->m_mtu);
                goto out;
            }
            memcpy(device_write_buf + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next));

        if (driver->m_debug >= 2) {
            CPE_INFO(
                device->m_driver->m_em,
                "%s: OUT: %d |       %s", device->m_netif.name, len,
                net_tun_dump_raw_data(net_tun_driver_tmp_buffer(driver), NULL, device_write_buf, NULL));
        }
        
        net_tun_device_send(device, device_write_buf, len);
    }

out:
    return ERR_OK;
}

static err_t net_tun_device_netif_output_ip4(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
    return net_tun_device_netif_do_output(netif, p);
}

static err_t net_tun_device_netif_output_ip6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr) {
    return net_tun_device_netif_do_output(netif, p);
}

static err_t net_tun_device_netif_input(struct pbuf *p, struct netif * netif) {
    //net_tun_device_t device = netif->state;
    //net_tun_driver_t driver = device->m_driver;
    
    uint8_t ip_version = 0;
    if (p->len > 0) {
        ip_version = (((uint8_t *)p->payload)[0] >> 4);
    }

    switch(ip_version) {
    case 4:
        return ip_input(p, netif);
    case 6:
        return ip6_input(p, netif);
    }

    pbuf_free(p);

    return ERR_OK;
}

static err_t net_tun_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    net_tun_device_t device = arg;
    net_tun_driver_t driver = device->m_driver;
    net_address_t local_addr = NULL;

    assert(err == ERR_OK);

    uint8_t is_ipv6 = PCB_ISIPV6(newpcb) ? 1 : 0;

    struct tcp_pcb *this_listener = is_ipv6 ? device->m_listener_ip6 : device->m_listener_ip4;
    assert(this_listener);
    tcp_accepted(this_listener);

    local_addr = net_address_from_lwip(driver, is_ipv6, &newpcb->local_ip, newpcb->local_port);
    if (local_addr == NULL) {
        CPE_ERROR(driver->m_em, "%s: accept: create local address fail", device->m_netif.name);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    net_tun_acceptor_t acceptor = net_tun_acceptor_find(driver, local_addr);
    if (acceptor == NULL) {
        if (driver->m_debug) {
            CPE_INFO(driver->m_em, "%s: accept: no acceptor", device->m_netif.name);
        }
        net_address_free(local_addr);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    if (net_tun_acceptor_on_accept( acceptor, newpcb, local_addr) != 0) {
        net_address_free(local_addr);
        tcp_abort(newpcb);
        return ERR_ABRT;
    }
    
    net_address_free(local_addr);
    return ERR_OK;
}
