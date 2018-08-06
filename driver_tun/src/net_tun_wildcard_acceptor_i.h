#ifndef NET_TUN_WILDCARD_ACCEPTOR_I_H_INCLEDED
#define NET_TUN_WILDCARD_ACCEPTOR_I_H_INCLEDED
#include "net_tun_wildcard_acceptor.h"
#include "net_tun_driver_i.h"

struct net_tun_wildcard_acceptor {
    net_tun_driver_t m_driver;
    TAILQ_ENTRY(net_tun_wildcard_acceptor) m_next;
    net_tun_wildcard_acceptor_mode_t m_mode;
    net_protocol_t m_protocol;
    net_acceptor_on_new_endpoint_fun_t m_on_new_endpoint;
    void * m_on_new_endpoint_ctx;
    net_ipset_t m_ipset;
};

#endif
