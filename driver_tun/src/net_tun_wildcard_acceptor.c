#include "net_ipset.h"
#include "net_tun_wildcard_acceptor_i.h"

net_tun_wildcard_acceptor_t
net_tun_wildcard_acceptor_create(
    net_tun_driver_t driver,
    net_tun_wildcard_acceptor_mode_t mode,
    net_protocol_t protocol,
    net_acceptor_on_new_endpoint_fun_t on_new_endpoint, void * on_new_endpoint_ctx)
{
    net_tun_wildcard_acceptor_t acceptor = mem_alloc(driver->m_alloc, sizeof(struct net_tun_wildcard_acceptor));
    if (acceptor == NULL) {
        CPE_ERROR(driver->m_em, "tun: wildcard acceptor: alloc fail!");
        return NULL;
    }

    acceptor->m_driver = driver;
    acceptor->m_mode = mode;
    acceptor->m_ipset = NULL;
    acceptor->m_protocol = protocol;
    acceptor->m_on_new_endpoint = on_new_endpoint;
    acceptor->m_on_new_endpoint_ctx = on_new_endpoint_ctx;
    
    TAILQ_INSERT_TAIL(&driver->m_wildcard_acceptors, acceptor, m_next);
    
    return acceptor;
}

void net_tun_wildcard_acceptor_free(net_tun_wildcard_acceptor_t wildcard_acceptor) {
    net_tun_driver_t driver = wildcard_acceptor->m_driver;

    if (wildcard_acceptor->m_ipset) {
        net_ipset_free(wildcard_acceptor->m_ipset);
        wildcard_acceptor->m_ipset = NULL;
    }

    TAILQ_REMOVE(&driver->m_wildcard_acceptors, wildcard_acceptor, m_next);
    
    mem_free(driver->m_alloc, wildcard_acceptor);
}

net_tun_wildcard_acceptor_mode_t net_tun_wildcard_acceptor_mode(net_tun_wildcard_acceptor_t wildcard_acceptor) {
    return wildcard_acceptor->m_mode;
}

net_ipset_t net_tun_wildcard_acceptor_ipset(net_tun_wildcard_acceptor_t wildcard_acceptor) {
    return wildcard_acceptor->m_ipset;
}

net_ipset_t net_tun_wildcard_acceptor_ipset_check_create(net_tun_wildcard_acceptor_t wildcard_acceptor) {
    if (wildcard_acceptor->m_ipset == NULL) {
        net_tun_driver_t driver = wildcard_acceptor->m_driver;
        wildcard_acceptor->m_ipset = net_ipset_create(net_tun_driver_schedule(driver));
        if (wildcard_acceptor->m_ipset == NULL) {
            CPE_ERROR(driver->m_em, "tun: wildcard_acceptor create ipset fail!");
            return NULL;
        }
    }

    return wildcard_acceptor->m_ipset;
}
