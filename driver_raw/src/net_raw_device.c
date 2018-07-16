#include "assert.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/pal/pal_stdio.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "net_endpoint.h"
#include "net_driver.h"
#include "net_address.h"
#include "net_raw_device_i.h"
#include "net_raw_utils.h"
#include "net_raw_endpoint.h"
#include "net_raw_device_listener_i.h"

static int net_raw_device_init_netif(net_raw_device_t device, net_address_t ip, net_address_t mask);
static int net_raw_device_init_listener_ip4(net_raw_device_t device);

static err_t net_raw_device_netif_init(struct netif *netif);
static err_t net_raw_device_netif_input(struct pbuf *p, struct netif *inp);
static err_t net_raw_device_netif_output_ip4(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr);
static err_t net_raw_device_netif_output_ip6(struct netif *netif, struct pbuf *p, ip6_addr_t *ipaddr);

static err_t net_raw_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

int net_raw_device_init(
    net_raw_device_t device, net_raw_driver_t driver, net_raw_device_type_t type, 
    net_address_t ip, net_address_t mask, uint16_t frame_mtu)
{
    device->m_driver = driver;
    device->m_type = type;
    device->m_frame_mtu = frame_mtu;
    device->m_listener_ip4 = NULL;
    device->m_listener_ip6 = NULL;
    device->m_quitting = 0;

    if (cpe_hash_table_init(
            &device->m_listeners,
            driver->m_alloc,
            (cpe_hash_fun_t) net_raw_device_listener_hash,
            (cpe_hash_eq_t) net_raw_device_listener_eq,
            CPE_HASH_OBJ2ENTRY(net_raw_device_listener, m_hh),
            -1) != 0)
    {
        return -1;
    }
    
    if (net_raw_device_init_netif(device, ip, mask) != 0) {
        cpe_hash_table_fini(&device->m_listeners);
        return -1;
    }

    if (net_raw_device_init_listener_ip4(device) != 0) {
        cpe_hash_table_fini(&device->m_listeners);
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

    net_raw_device_listener_free_all(device);
    cpe_hash_table_fini(&device->m_listeners);
    
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

const char * net_raw_device_name(net_raw_device_t device) {
    return device->m_netif.name;
}

net_raw_device_t net_raw_device_default(net_raw_driver_t driver) {
    return driver->m_default_device;
}

static int net_raw_device_init_netif(net_raw_device_t device, net_address_t ip, net_address_t mask) {
    // make addresses for netif
    ip_addr_t addr;
    if (ip) {
        net_address_to_lwip_ipv4(&addr, ip);
    }
    else {
        ip_addr_set_any(&addr);
    }
    
    ip_addr_t netmask;
    if (mask) {
        net_address_to_lwip_ipv4(&netmask, mask);
    }
    else {
        ip_addr_set_any(&netmask);
    }
    
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
    net_raw_driver_t driver = device->m_driver;

    if (device->m_quitting) {
        return ERR_OK;
    }

    if (!p->next) {
        if (p->len > device->m_frame_mtu) {
            CPE_ERROR(
                driver->m_em, "%s: output: len %d overflow, mtu=%d",
                device->m_netif.name, p->len, device->m_frame_mtu);
            goto out;
        }

        if (driver->m_debug >= 2) {
            CPE_INFO(
                device->m_driver->m_em,
                "%s: OUT: %d |      %s", device->m_netif.name, p->len,
                net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), NULL, (uint8_t *)p->payload, NULL));
        }

        device->m_type->send(device, (uint8_t *)p->payload, p->len);
    }
    else {
        void * device_write_buf = mem_buffer_alloc(net_raw_driver_tmp_buffer(device->m_driver), device->m_frame_mtu);
        int len = 0;
        do {
            if (p->len > device->m_frame_mtu - len) {
                CPE_ERROR(
                    device->m_driver->m_em, "%s: output: len %d overflow, mtu=%d",
                    device->m_netif.name, p->len + len, device->m_frame_mtu);
                goto out;
            }
            memcpy(device_write_buf + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next));

        if (driver->m_debug >= 2) {
            CPE_INFO(
                device->m_driver->m_em,
                "%s: OUT: %d |       %s", device->m_netif.name, len,
                net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), NULL, device_write_buf, NULL));
        }
        
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

static err_t net_raw_device_netif_input(struct pbuf *p, struct netif * netif) {
    net_raw_device_t device = netif->state;
    net_raw_driver_t driver = device->m_driver;
    
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

static err_t net_raw_device_netif_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    net_raw_device_t device = arg;
    net_raw_driver_t driver = device->m_driver;
    net_driver_t base_driver = net_driver_from_data(driver);
    net_schedule_t schedule = net_raw_driver_schedule(driver);
    net_endpoint_t base_endpoint = NULL;
    net_address_t local_addr = NULL;
    net_address_t remote_addr = NULL;

    assert(err == ERR_OK);

    uint8_t is_ipv6 = PCB_ISIPV6(newpcb) ? 1 : 0;

    struct tcp_pcb *this_listener = is_ipv6 ? device->m_listener_ip6 : device->m_listener_ip4;
    assert(this_listener);
    tcp_accepted(this_listener);

    local_addr = net_address_from_lwip(driver, is_ipv6, &newpcb->local_ip, newpcb->local_port);
    if (local_addr == NULL) {
        CPE_ERROR(driver->m_em, "%s: accept: create local address fail", device->m_netif.name);
        goto accept_error; 
    }

    net_raw_device_listener_t listener = net_raw_device_listener_find(device, local_addr);
    if (listener == NULL) {
        if (driver->m_debug) {
            CPE_INFO(driver->m_em, "%s: accept: no listener", device->m_netif.name);
        }
        goto accept_error;
    }

    base_endpoint = net_endpoint_create(base_driver, net_endpoint_inbound, listener->m_protocol);
    if (base_endpoint == NULL) {
        CPE_ERROR(driver->m_em, "%s: accept: create endpoint fail", device->m_netif.name);
        goto accept_error; 
    }

    if (net_endpoint_set_address(base_endpoint, local_addr, 1) != 0) {
        CPE_ERROR(driver->m_em, "%s: accept: set address fail", device->m_netif.name);
        net_address_free(local_addr);
        goto accept_error; 
    }
    local_addr = NULL;

    remote_addr = net_address_from_lwip(driver, is_ipv6, &newpcb->remote_ip, newpcb->remote_port);
    if (net_endpoint_set_remote_address(base_endpoint, remote_addr, 1) != 0) {
        CPE_ERROR(device->m_driver->m_em, "%s: accept: set address fail", device->m_netif.name);
        goto accept_error; 
    }
    remote_addr = NULL;

    if (listener->m_on_accept) {
        if (listener->m_on_accept(listener->m_on_accept_ctx, base_endpoint) != 0) {
            CPE_ERROR(device->m_driver->m_em, "%s: accept: on accept fail", device->m_netif.name);
            goto accept_error; 
        }
    }
    
    struct net_raw_endpoint * endpoint = net_endpoint_data(base_endpoint);
    net_raw_endpoint_set_pcb(endpoint, newpcb);
    newpcb = NULL;

    if (net_endpoint_set_state(base_endpoint, net_endpoint_state_established) != 0) {
        goto accept_error;
    }

    if (driver->m_debug >= 2) {
        CPE_INFO(device->m_driver->m_em, "%s: accept: success", device->m_netif.name);
    }

    return ERR_OK;

accept_error:
    if (base_endpoint) {
        net_endpoint_free(base_endpoint);
    }

    if (local_addr) {
        net_address_free(local_addr);
    }

    if (remote_addr) {
        net_address_free(remote_addr);
    }

    if (newpcb) {
        tcp_abort(newpcb);
    }
    
    return ERR_ABRT;
}
