#include "assert.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "net_dgram.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_tun_dgram.h"
#include "net_tun_utils.h"

static void net_tun_dgram_recv_ipv4(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *addr, u16_t port);
static void net_tun_dgram_recv_ipv6(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip6_addr_t *addr, u16_t port);

int net_tun_dgram_init(net_dgram_t base_dgram) {
    net_tun_dgram_t dgram = net_dgram_data(base_dgram);
    net_tun_driver_t driver = net_driver_data(net_dgram_driver(base_dgram));
    
    net_address_t address = net_dgram_address(base_dgram);
    if (address) {
        switch(net_address_type(address)) {
        case net_address_ipv4: {
            dgram->m_pcb = udp_new();
            if (dgram->m_pcb == NULL) {
                CPE_ERROR(driver->m_em, "tun: dgram: udp_pcb create error");
                return -1;
            }

            ip_addr_t addr;
            net_address_to_lwip_ipv4(&addr, address);
            err_t err = udp_bind(dgram->m_pcb, &addr, net_address_port(address));
            if (err) {
                CPE_ERROR(
                    driver->m_em, "tun: dgram: udp_pcb bind to %s fail, err=%d (%s)",
                    net_address_dump(net_tun_driver_tmp_buffer(driver), address),
                    err, lwip_strerr(err));
                udp_remove(dgram->m_pcb);
                dgram->m_pcb = NULL;
                return -1;
            }
            
            break;
        }
        case net_address_ipv6: {
            dgram->m_pcb = udp_new_ip6();
            if (dgram->m_pcb == NULL) {
                CPE_ERROR(driver->m_em, "tun: dgram: udp_pcb create error");
                return -1;
            }

            ip6_addr_t addr;
            net_address_to_lwip_ipv6(&addr, address);
            err_t err = udp_bind_ip6(dgram->m_pcb, &addr, net_address_port(address));
            if (err) {
                CPE_ERROR(
                    driver->m_em, "tun: dgram: udp_pcb bind to %s fail, err=%d (%s)",
                    net_address_dump(net_tun_driver_tmp_buffer(driver), address),
                    err, lwip_strerr(err));
                udp_remove(dgram->m_pcb);
                dgram->m_pcb = NULL;
                return -1;
            }

            break;
        }
        case net_address_domain:
            CPE_ERROR(driver->m_em, "tun: dgyam: not support domain address!");
            return -1;
        }

        if (net_dgram_driver_debug(base_dgram)) {
            CPE_INFO(
                driver->m_em, "tun: dgram: bind to %s",
                net_address_dump(net_tun_driver_tmp_buffer(driver), address));
        }
    }
    else {
        dgram->m_pcb = udp_new();
        if (dgram->m_pcb == NULL) {
            CPE_ERROR(driver->m_em, "tun: dgram: udp_pcb create error");
            return -1;
        }
    }

    udp_recv(dgram->m_pcb, net_tun_dgram_recv_ipv4, base_dgram);
    udp_recv_ip6(dgram->m_pcb, net_tun_dgram_recv_ipv6, base_dgram);
    
    return 0;
}

void net_tun_dgram_fini(net_dgram_t base_dgram) {
    net_tun_dgram_t dgram = net_dgram_data(base_dgram);
    //net_tun_driver_t driver = net_driver_data(net_dgram_driver(base_dgram));

    if (dgram->m_pcb) {
        udp_recv(dgram->m_pcb, NULL, NULL);
        udp_recv_ip6(dgram->m_pcb, NULL, NULL);
        udp_remove(dgram->m_pcb);
        dgram->m_pcb = NULL;
    }
}

int net_tun_dgram_send(net_dgram_t base_dgram, net_address_t target, void const * data, size_t data_len) {
    net_tun_dgram_t dgram = net_dgram_data(base_dgram);
    net_tun_driver_t driver = net_driver_data(net_dgram_driver(base_dgram));

    switch(net_address_type(target)) {
    case net_address_ipv4: {
        ip_addr_t addr;
        net_address_to_lwip_ipv4(&addr, target);

        struct pbuf * p = pbuf_alloc(PBUF_TRANSPORT, (uint16_t)data_len, PBUF_POOL);
        if (p == NULL) {
            CPE_ERROR(
                driver->m_em, "tun: dgram: send to %s: pbuf alloc fail, len=%d",
                net_address_dump(net_tun_driver_tmp_buffer(driver), target),
                (int)data_len);
            return -1;
        }

        pbuf_take(p, (char*)data, (uint16_t)data_len);
         
        err_t err = udp_sendto(dgram->m_pcb, p, &addr, net_address_port(target));
        if (err) {
            CPE_ERROR(
                driver->m_em, "tun: dgram: send to %s fail, err=%d (%s)",
                net_address_dump(net_tun_driver_tmp_buffer(driver), target),
                err, lwip_strerr(err));
            pbuf_free(p);
            return -1;
        }

        pbuf_free(p);
        break;
    }
    case net_address_ipv6: {
        ip6_addr_t addr;
        net_address_to_lwip_ipv6(&addr, target);

        struct pbuf * p = pbuf_alloc(PBUF_TRANSPORT, (uint16_t)data_len, PBUF_POOL);
        if (p == NULL) {
            CPE_ERROR(
                driver->m_em, "tun: dgram: send to %s: pbuf alloc fail, len=%d",
                net_address_dump(net_tun_driver_tmp_buffer(driver), target),
                (int)data_len);
            return -1;
        }

        pbuf_take(p, (char*)data, (uint16_t)data_len);
         
        err_t err = udp_sendto_ip6(dgram->m_pcb, p, &addr, net_address_port(target));
        if (err) {
            CPE_ERROR(
                driver->m_em, "tun: dgram: send to %s fail, err=%d (%s)",
                net_address_dump(net_tun_driver_tmp_buffer(driver), target),
                err, lwip_strerr(err));
            pbuf_free(p);
            return -1;
        }

        pbuf_free(p);
        break;
    }
    default:
        CPE_ERROR(driver->m_em, "tun: dgyam: not support send to domain address!");
        return -1;
    }

    if (net_dgram_driver_debug(base_dgram)) {
        CPE_INFO(
            driver->m_em, "turn: dgram: send %d data to %s",
            (int)data_len,
            net_address_dump(net_tun_driver_tmp_buffer(driver), target));
    }
    
    return (int)data_len;
}

static void net_tun_dgram_do_recv(
    net_dgram_t base_dgram, net_tun_driver_t driver, net_tun_dgram_t dgram, struct pbuf *p, net_address_t from)
{
    char buf[1500];

    uint32_t size = p->tot_len;
    if (size > sizeof(buf)) {
        CPE_ERROR(driver->m_em, "tun: dgram: receive data len %d overflow!", size);
        return;
    }
    
    u16_t read_sz = pbuf_copy_partial(p, buf, size, 0);
    assert(read_sz == size);
    
    net_dgram_recv(base_dgram, from, buf, (size_t)read_sz);

    if (driver->m_data_monitor_fun) {
        driver->m_data_monitor_fun(driver->m_data_monitor_ctx, NULL, net_data_in, (uint32_t)read_sz);
    }
}

static void net_tun_dgram_recv_ipv4(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *addr, u16_t port) {
    net_dgram_t base_dgram = arg;
    net_tun_dgram_t dgram = net_dgram_data(base_dgram);
    net_tun_driver_t driver = net_driver_data(net_dgram_driver(base_dgram));
    
    net_address_t from = net_address_from_lwip(driver, 0, (ipX_addr_t *)addr, port);
    if (from == NULL) {
        CPE_ERROR(driver->m_em, "tun: dgram: create source address fail!");
        return;
    }

    net_tun_dgram_do_recv(base_dgram, driver, dgram, p, from);
    
    net_address_free(from);
}

static void net_tun_dgram_recv_ipv6(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip6_addr_t *addr, u16_t port) {
    net_dgram_t base_dgram = arg;
    net_tun_dgram_t dgram = net_dgram_data(base_dgram);
    net_tun_driver_t driver = net_driver_data(net_dgram_driver(base_dgram));
    
    net_address_t from = net_address_from_lwip(driver, 0, (ipX_addr_t *)addr, port);
    if (from == NULL) {
        CPE_ERROR(driver->m_em, "tun: dgram: create source address fail!");
        return;
    }

    net_tun_dgram_do_recv(base_dgram, driver, dgram, p, from);
    
    net_address_free(from);
}
