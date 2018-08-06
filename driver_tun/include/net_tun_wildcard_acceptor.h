#ifndef NET_TUN_WILDCARD_ACCEPTOR_H_INCLEDED
#define NET_TUN_WILDCARD_ACCEPTOR_H_INCLEDED
#include "net_tun_types.h"

NET_BEGIN_DECL

net_tun_wildcard_acceptor_t
net_tun_wildcard_acceptor_create(
    net_tun_driver_t driver, 
    net_tun_wildcard_acceptor_mode_t mode,
    net_protocol_t protocol,
    net_acceptor_on_new_endpoint_fun_t on_new_endpoint, void * on_new_endpoint_ctx);

void net_tun_wildcard_acceptor_free(net_tun_wildcard_acceptor_t whildcard_acceptor);

net_tun_wildcard_acceptor_mode_t net_tun_wildcard_acceptor_mode(net_tun_wildcard_acceptor_t whildcard_acceptor);

net_ipset_t net_tun_wildcard_acceptor_ipset(net_tun_wildcard_acceptor_t whildcard_acceptor);
net_ipset_t net_tun_wildcard_acceptor_ipset_check_create(net_tun_wildcard_acceptor_t whildcard_acceptor);

NET_END_DECL

#endif
