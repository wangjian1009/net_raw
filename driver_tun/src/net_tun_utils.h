#ifndef NET_TUN_UTILS_H_INCLEDED
#define NET_TUN_UTILS_H_INCLEDED
#include "net_tun_driver_i.h"

void net_tun_print_raw_data(
    write_stream_t ws, uint8_t const * iphead, uint32_t packet_size, uint8_t dump_content);
const char * net_tun_dump_raw_data(
    mem_buffer_t tmp_buffer, uint8_t const * iphead, uint32_t packet_size, uint8_t dump_content);

net_address_t net_tun_iphead_source_addr(net_tun_driver_t driver, uint8_t const * iphead);
net_address_t net_tun_iphead_target_addr(net_tun_driver_t driver, uint8_t const * iphead);

net_address_t net_address_from_lwip(net_tun_driver_t driver, const ip_addr_t * addr, uint16_t port);

void net_address_to_lwip_ipv4(ip4_addr_t * addr, net_address_t address);
void net_address_to_lwip_ipv6(ip6_addr_t * addr, net_address_t address);

#endif
