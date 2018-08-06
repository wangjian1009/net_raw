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

