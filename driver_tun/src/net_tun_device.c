#include <assert.h>
#include "net_tun_driver_i.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/pal/pal_unistd.h"
#include "cpe/utils/string_utils.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_acceptor.h"
#include "net_endpoint.h"
#include "net_ipset.h"
#include "net_tun_device_i.h"
#include "net_tun_utils.h"
#include "net_tun_acceptor_i.h"
#include "net_tun_wildcard_acceptor_i.h"
#include "net_tun_endpoint.h"

static int net_tun_device_init_netif(net_tun_device_t device, net_tun_device_netif_options_t netif_settings);
static int net_tun_device_init_listener_ip4(net_tun_device_t device);
static int net_tun_device_init_listener_ip6(net_tun_device_t device);

static err_t net_tun_device_netif_init(struct netif *netif);
static err_t net_tun_device_netif_input(struct pbuf *p, struct netif *inp);
static err_t net_tun_device_netif_output_ip4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
static err_t net_tun_device_netif_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr);

net_tun_device_t
net_tun_device_create(
    net_tun_driver_t driver, net_tun_device_init_data_t settings, net_tun_device_netif_options_t netif_settings)
{
    net_driver_t base_driver = net_driver_from_data(driver);

    net_tun_device_t device = mem_alloc(driver->m_alloc, sizeof(struct net_tun_device));
    if (device == NULL) {
        CPE_ERROR(driver->m_em, "tun: device alloc fail!");
        return NULL;
    }

    device->m_driver = driver;
    device->m_listener_ip4 = NULL;
    device->m_listener_ip6 = NULL;
    device->m_mtu = 0;
    device->m_write_combine_buf = NULL;
    device->m_quitting = 0;
    device->m_dev_name[0] = 0;
    
    if (net_tun_device_init_dev(driver, device, settings) != 0) {
        mem_free(driver->m_alloc, device);
        return NULL;
    }

    assert(device->m_mtu > 0);
    assert(device->m_write_combine_buf == NULL);
    device->m_write_combine_buf = mem_alloc(driver->m_alloc, device->m_mtu);
    if (device->m_write_combine_buf == NULL) {
        CPE_ERROR(
            driver->m_em, "tun: dev %s: alloc write buf fail, mtu=%d",
            device->m_dev_name, device->m_mtu);
        goto create_errror;
    }
    
    uint8_t netif_init = 0;
    if (net_tun_device_init_netif(device, netif_settings) != 0) {
        goto create_errror;
    }
    netif_init = 1;

    if (net_tun_device_init_listener_ip4(device) != 0) {
        goto create_errror;
    }

    if (netif_settings && netif_settings->m_ipv6_address) {
        if (net_tun_device_init_listener_ip6(device) != 0) {
            goto create_errror;
        }
    }
    
    if (driver->m_default_device == NULL) {
        driver->m_default_device = device;
        netif_set_default(&device->m_netif);
    }
    TAILQ_INSERT_TAIL(&driver->m_devices, device, m_next_for_driver);
    
    if (net_driver_debug(base_driver) > 0) {
        CPE_INFO(
            driver->m_em, "tun: device: created: name=%s, mtu=%d",
            device->m_dev_name, device->m_mtu);
    }
    
    return device;

create_errror:
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

    if (device->m_write_combine_buf) {
        mem_free(driver->m_alloc, device->m_write_combine_buf);
        device->m_write_combine_buf = NULL;
    }
    
    mem_free(driver->m_alloc, device);

    return NULL;
}

void net_tun_device_free(net_tun_device_t device) {
    net_tun_driver_t driver = device->m_driver;
    net_driver_t base_driver = net_driver_from_data(driver);

    if (net_driver_debug(base_driver) > 0) {
        CPE_INFO(driver->m_em, "tun: device: free");
    }
    
    device->m_quitting = 1;

    net_tun_device_fini_dev(driver, device);
    
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

    if (device->m_write_combine_buf) {
        mem_free(driver->m_alloc, device->m_write_combine_buf);
        device->m_write_combine_buf = NULL;
    }
    
    mem_free(driver->m_alloc, device);
}

const char * net_tun_device_name(net_tun_device_t device) {
    return device->m_dev_name;
}

net_tun_device_t net_tun_device_default(net_tun_driver_t driver) {
    return driver->m_default_device;
}

static int net_tun_device_init_netif(
    net_tun_device_t device, net_tun_device_netif_options_t netif_settings)
{
    // make addresses for netif
    ip4_addr_t addr;
    ip4_addr_t netmask;

    if (netif_settings == NULL || netif_settings->m_ipv4_address == NULL) {
        ip4_addr_set_any(&addr);
        ip4_addr_set_any(&netmask);
    }
    else {
        if (netif_settings->m_ipv4_mask == NULL) {
            CPE_ERROR(device->m_driver->m_em, "tun: %s: have ipv4 address, but no ipv4 mask!", device->m_dev_name);
            return -1;
        }

        net_address_to_lwip_ipv4(&addr, netif_settings->m_ipv4_address);
        net_address_to_lwip_ipv4(&netmask, netif_settings->m_ipv4_mask);
    }
    
    ip4_addr_t gw;
    ip4_addr_set_any(&gw);

    bzero(&device->m_netif, sizeof(device->m_netif));
    if (!netif_add(&device->m_netif, &addr, &netmask, &gw, device, net_tun_device_netif_init, net_tun_device_netif_input)) {
        CPE_ERROR(device->m_driver->m_em, "tun: device: add netif fail!");
        return -1;
    }

    netif_set_up(&device->m_netif);
    netif_set_link_up(&device->m_netif);
    netif_set_pretend_tcp(&device->m_netif, 1);

    if (netif_settings->m_ipv6_address) {
        // add IPv6 address
        ip6_addr_t ip6addr;
        net_address_to_lwip_ipv6(&ip6addr, netif_settings->m_ipv6_address);
        netif_ip6_addr_set(&device->m_netif, 0, &ip6addr);
        netif_ip6_addr_set_state(&device->m_netif, 0, IP6_ADDR_VALID);
    }
    
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
    net_driver_t base_driver = net_driver_from_data(driver);

    if (device->m_quitting) {
        return ERR_OK;
    }

    if (!p->next) {
        if (p->len > device->m_mtu) {
            CPE_ERROR(
                driver->m_em, "tun: %s: output: len %d overflow, mtu=%d",
                device->m_dev_name, p->len, device->m_mtu);
            goto out;
        }

        net_tun_device_packet_write(device, (uint8_t *)p->payload, p->len);
    }
    else {
        assert(device->m_write_combine_buf);

        void * device_write_buf = device->m_write_combine_buf;
        int len = 0;
        do {
            if (p->len > device->m_mtu - len) {
                CPE_ERROR(
                    driver->m_em, "tun: %s: output: len %d overflow, mtu=%d",
                    device->m_dev_name, p->len + len, device->m_mtu);
                goto out;
            }
            memcpy((uint8_t*)device_write_buf + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next));

        net_tun_device_packet_write(device, device_write_buf, len);
    }

out:
    return ERR_OK;
}

static err_t net_tun_device_netif_output_ip4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    return net_tun_device_netif_do_output(netif, p);
}

static err_t net_tun_device_netif_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    return net_tun_device_netif_do_output(netif, p);
}

static err_t net_tun_device_netif_input(struct pbuf *p, struct netif * netif) {
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

int net_tun_device_packet_input(net_tun_driver_t driver, net_tun_device_t device, uint8_t const * packet_data, uint16_t packet_size) {
    net_driver_t base_driver = net_driver_from_data(driver);

    if (packet_size > device->m_mtu) {
        CPE_ERROR(
            driver->m_em, "tun: %s: input packet length %d overflow, mtu=%d",
            device->m_dev_name, packet_size, device->m_mtu);
        return -1;
    }

    uint8_t const * iphead = packet_data;
    uint8_t const * data = iphead + TCP_HLEN;

    if (net_driver_debug(base_driver) >= 2) {
        CPE_INFO(
            driver->m_em, "tun: %s: <<< %.5d |      %s",
            device->m_dev_name, packet_size,
            net_tun_dump_raw_data(
                net_tun_driver_tmp_buffer(driver), iphead, packet_size,
                net_driver_debug(base_driver) >= 3));
    }
            
    struct pbuf *p = pbuf_alloc(PBUF_RAW, packet_size, PBUF_POOL);
    if (!p) {
        CPE_ERROR(driver->m_em, "tun: %s: packet input: pbuf_alloc fail", device->m_dev_name);
        return -1;
    }

    err_t err = pbuf_take(p, iphead, packet_size);
    if (err != ERR_OK) {
        CPE_ERROR(driver->m_em, "tun: %s: packet input: pbuf_take fail, error=%d (%s)", device->m_dev_name, err, lwip_strerr(err));
        pbuf_free(p);
        return -1;
    }

    err = device->m_netif.input(p, &device->m_netif);
    if (err != ERR_OK) {
        CPE_ERROR(driver->m_em, "tun: %s: packet input: input fail, error=%d (%s)", device->m_dev_name, err, lwip_strerr(err));
        pbuf_free(p);
        return -1;
    }
    
    return 0;
}

void net_tun_device_clear_all(net_tun_driver_t driver) {
    while(!TAILQ_EMPTY(&driver->m_devices)) {
        net_tun_device_free(TAILQ_FIRST(&driver->m_devices));
    }
}

void net_tun_device_netif_options_clear(net_tun_device_netif_options_t netif_options) {
    if (netif_options->m_ipv6_address) {
        net_address_free(netif_options->m_ipv6_address);
        netif_options->m_ipv6_address = NULL;
    }

    if (netif_options->m_ipv4_address) {
        net_address_free(netif_options->m_ipv4_address);
        netif_options->m_ipv4_address = NULL;
    }

    if (netif_options->m_ipv4_mask) {
        net_address_free(netif_options->m_ipv4_mask);
        netif_options->m_ipv4_mask = NULL;
    }
}

static int net_tun_device_do_accept(
    net_tun_device_t device,
    net_tun_acceptor_t acceptor, net_tun_wildcard_acceptor_t wildcard_acceptor,
    struct tcp_pcb *newpcb, net_address_t local_addr)
{
    net_tun_driver_t driver = device->m_driver;
    net_driver_t base_driver = net_driver_from_data(driver);

    net_acceptor_t base_acceptor = acceptor ? net_acceptor_from_data(acceptor) : NULL;
    net_protocol_t protocol = base_acceptor ? net_acceptor_protocol(base_acceptor) : wildcard_acceptor->m_protocol;
        
    net_endpoint_t base_endpoint = net_endpoint_create(base_driver, protocol, NULL);
    if (base_endpoint == NULL) {
        CPE_ERROR(driver->m_em, "tun: accept: create endpoint fail");
        return -1;
    }

    net_tun_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    net_tun_endpoint_set_pcb(endpoint, newpcb);
    newpcb = NULL;
    
    if (net_endpoint_set_address(base_endpoint, local_addr) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: set address fail");
        net_tun_endpoint_set_pcb(endpoint, NULL);
        net_endpoint_free(base_endpoint);
        return -1;
    }

    assert(endpoint->m_pcb);
    net_address_t remote_addr = net_address_from_lwip(driver, &endpoint->m_pcb->remote_ip, endpoint->m_pcb->remote_port);
    if (net_endpoint_set_remote_address(base_endpoint, remote_addr) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: set remote address fail");
        net_tun_endpoint_set_pcb(endpoint, NULL);
        net_endpoint_free(base_endpoint);
        net_address_free(remote_addr);
        return -1;
    }
    net_address_free(remote_addr);
    remote_addr = NULL;

    if (net_endpoint_set_state(base_endpoint, net_endpoint_state_established) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: set state fail");
        net_tun_endpoint_set_pcb(endpoint, NULL);
        net_endpoint_free(base_endpoint);
        return -1;
    }
    
    int external_init_rv = base_acceptor
        ? net_acceptor_on_new_endpoint(base_acceptor, base_endpoint)
        : wildcard_acceptor->m_on_new_endpoint(wildcard_acceptor->m_on_new_endpoint_ctx, base_endpoint);
    if (external_init_rv != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: on accept fail");
        net_tun_endpoint_set_pcb(endpoint, NULL);
        net_endpoint_free(base_endpoint);
        return -1;
    }
    
    if (net_driver_debug(base_driver) >= 2) {
        CPE_INFO(driver->m_em, "tun: accept: success");
    }

    return 0;
}

static err_t net_tun_device_on_accept(
    net_tun_device_t device, struct tcp_pcb * newpcb, err_t err, struct tcp_pcb * this_listener)
{
    net_tun_driver_t driver = device->m_driver;
    net_driver_t base_driver = net_driver_from_data(driver);
    net_address_t local_addr = NULL;

    assert(err == ERR_OK);

    assert(this_listener);
    tcp_accepted(this_listener);

    local_addr = net_address_from_lwip(driver, &newpcb->local_ip, newpcb->local_port);
    if (local_addr == NULL) {
        CPE_ERROR(driver->m_em, "tun: accept: create local address fail");
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    net_tun_acceptor_t acceptor = net_tun_acceptor_find(driver, local_addr);
    if (acceptor) {
        if (net_tun_device_do_accept(device, acceptor, NULL, newpcb, local_addr) != 0) {
            net_address_free(local_addr);
            tcp_abort(newpcb);
            return ERR_ABRT;
        }

        net_address_free(local_addr);
        return ERR_OK;
    }

    net_tun_wildcard_acceptor_t wildcard_acceptor;
    TAILQ_FOREACH(wildcard_acceptor, &driver->m_wildcard_acceptors, m_next) {
        switch(wildcard_acceptor->m_mode) {
        case net_tun_wildcard_acceptor_mode_white:
            if (wildcard_acceptor->m_ipset == NULL
                || !net_ipset_contains_ip(wildcard_acceptor->m_ipset, local_addr)
                )
            {
                continue;
            }
            break;
        case net_tun_wildcard_acceptor_mode_black:
            if (wildcard_acceptor->m_ipset
                && net_ipset_contains_ip(wildcard_acceptor->m_ipset, local_addr)
                )
            {
                continue;
            }
            break;
        }

        if (net_tun_device_do_accept(device, NULL, wildcard_acceptor, newpcb, local_addr) != 0) {
            net_address_free(local_addr);
            tcp_abort(newpcb);
            return ERR_ABRT;
        }

        net_address_free(local_addr);
        return ERR_OK;
    }
    
    if (net_driver_debug(base_driver)) {
        CPE_INFO(
            driver->m_em, "tun: accept: no acceptor for %s",
            net_address_dump(net_tun_driver_tmp_buffer(device->m_driver), local_addr));
    }
    net_address_free(local_addr);
    tcp_abort(newpcb);
    return ERR_ABRT;
}

static err_t net_tun_device_on_accept_ipv4(void *arg, struct tcp_pcb * newpcb, err_t err) {
    net_tun_device_t device = arg;
    return net_tun_device_on_accept(device, newpcb, err, device->m_listener_ip4);
}

static err_t net_tun_device_on_accept_ipv6(void *arg, struct tcp_pcb * newpcb, err_t err) {
    net_tun_device_t device = arg;
    return net_tun_device_on_accept(device, newpcb, err, device->m_listener_ip6);
}

static int net_tun_device_init_listener_ip4(net_tun_device_t device) {
    net_tun_driver_t driver = device->m_driver;
    struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (l == NULL) {
        CPE_ERROR(driver->m_em, "tun: listener4: tcp_new failed");
        return -1;
    }

    // ensure the listener only accepts connections from this netif
    tcp_bind_netif(l, &device->m_netif);

    device->m_listener_ip4 = tcp_listen_with_backlog(l, TCP_DEFAULT_LISTEN_BACKLOG);
    if (device->m_listener_ip4 == NULL) {
        CPE_ERROR(driver->m_em, "tun: listener4: tcp_listen fail");
        tcp_close(l);
        return -1;
    }

    tcp_arg(device->m_listener_ip4, device);
    tcp_accept(device->m_listener_ip4, net_tun_device_on_accept_ipv4);

    return 0;
}

static int net_tun_device_init_listener_ip6(net_tun_device_t device) {
    net_tun_driver_t driver = device->m_driver;
    struct tcp_pcb * l = tcp_new_ip_type(IPADDR_TYPE_V6);
    if (l == NULL) {
        CPE_ERROR(driver->m_em, "tun:  listener6: tcp_new failed");
        return -1;
    }

    tcp_bind_netif(l, &device->m_netif);

    device->m_listener_ip6 = tcp_listen_with_backlog(l, TCP_DEFAULT_LISTEN_BACKLOG);
    if (device->m_listener_ip6 == NULL) {
        CPE_ERROR(driver->m_em, "tun:  listener6: tcp_listen fail");
        tcp_close(l);
        return -1;
    }

    tcp_arg(device->m_listener_ip6, device);
    tcp_accept(device->m_listener_ip6, net_tun_device_on_accept_ipv6);

    return 0;
}
