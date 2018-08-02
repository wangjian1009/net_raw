#include "net_acceptor.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_endpoint.h"
#include "net_tun_acceptor_i.h"
#include "net_tun_utils.h"
#include "net_tun_endpoint.h"

int net_tun_acceptor_init(net_acceptor_t base_acceptor) {
    net_tun_driver_t driver = net_driver_data(net_acceptor_driver(base_acceptor));
    net_tun_acceptor_t acceptor = net_acceptor_data(base_acceptor);
    net_address_t address = net_acceptor_address(base_acceptor);

    acceptor->m_address = address;
    cpe_hash_entry_init(&acceptor->m_hh);
    if (cpe_hash_table_insert_unique(&driver->m_acceptors, acceptor) != 0) {
        CPE_ERROR(
            driver->m_em, "tun: acceptor: address %s duplicate",
            net_address_dump(net_tun_driver_tmp_buffer(driver), address));
        return -1;
    }
    
    return 0;
}

void net_tun_acceptor_fini(net_acceptor_t base_acceptor) {
    net_tun_driver_t driver = net_driver_data(net_acceptor_driver(base_acceptor));
    net_tun_acceptor_t acceptor = net_acceptor_data(base_acceptor);
    cpe_hash_table_remove_by_ins(&driver->m_acceptors, acceptor);
}

net_tun_acceptor_t
net_tun_acceptor_find(net_tun_driver_t driver, net_address_t address) {
    struct net_tun_acceptor key;
    key.m_address = address;
    return cpe_hash_table_find(&driver->m_acceptors, &key);
}

int net_tun_acceptor_on_accept(net_tun_acceptor_t acceptor, struct tcp_pcb *newpcb, net_address_t local_addr) {
    net_acceptor_t base_acceptor = net_acceptor_from_data(acceptor);
    net_driver_t base_driver = net_acceptor_driver(base_acceptor);
    net_tun_driver_t driver = net_driver_data(base_driver);

    uint8_t is_ipv6 = PCB_ISIPV6(newpcb) ? 1 : 0;

    net_endpoint_t base_endpoint = net_endpoint_create(base_driver, net_endpoint_inbound, net_acceptor_protocol(base_acceptor));
    if (base_endpoint == NULL) {
        CPE_ERROR(driver->m_em, "tun: accept: create endpoint fail");
        return -1;
    }

    if (net_endpoint_set_address(base_endpoint, local_addr, 0) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: set address fail");
        net_endpoint_free(base_endpoint);
        return -1;
    }

    net_address_t remote_addr = net_address_from_lwip(driver, is_ipv6, &newpcb->remote_ip, newpcb->remote_port);
    if (net_endpoint_set_remote_address(base_endpoint, remote_addr, 1) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: set remote address fail");
        net_endpoint_free(base_endpoint);
        return -1;
    }
    remote_addr = NULL;

    if (net_acceptor_on_new_endpoint(base_acceptor, base_endpoint) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: on accept fail");
        net_endpoint_free(base_endpoint);
        return -1;
    }
    
    struct net_tun_endpoint * endpoint = net_endpoint_data(base_endpoint);
    net_tun_endpoint_set_pcb(endpoint, newpcb);
    newpcb = NULL;

    if (net_endpoint_set_state(base_endpoint, net_endpoint_state_established) != 0) {
        CPE_ERROR(driver->m_em, "tun: accept: set state fail");
        net_endpoint_free(base_endpoint);
        return -1;
    }

    if (driver->m_debug >= 2) {
        CPE_INFO(driver->m_em, "tun: accept: success");
    }

    return 0;
}

void net_tun_acceptor_free_all(net_tun_driver_t driver) {
    struct cpe_hash_it acceptor_it;
    net_tun_acceptor_t acceptor;

    cpe_hash_it_init(&acceptor_it, &driver->m_acceptors);

    acceptor = cpe_hash_it_next(&acceptor_it);
    while(acceptor) {
        net_tun_acceptor_t next = cpe_hash_it_next(&acceptor_it);
        net_acceptor_free(net_acceptor_from_data(acceptor));
        acceptor = next;
    }
}

uint32_t net_tun_acceptor_hash(net_tun_acceptor_t acceptor, void * user_data) {
    return net_address_hash(acceptor->m_address);
}

int net_tun_acceptor_eq(net_tun_acceptor_t l, net_tun_acceptor_t r, void * user_data) {
    return net_address_cmp(l->m_address, r->m_address) == 0 ? 1 : 0;
}

