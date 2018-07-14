#ifndef NET_RAW_UTILS_H_INCLEDED
#define NET_RAW_UTILS_H_INCLEDED
#include "net_raw_driver_i.h"

void net_raw_print_raw_data(write_stream_t ws, uint8_t * ethhead, uint8_t * iphead, uint8_t * data);
const char * net_raw_dump_raw_data(mem_buffer_t tmp_buffer, uint8_t * ethhead, uint8_t * iphead, uint8_t * data);

net_address_t net_raw_iphead_source_addr(net_raw_driver_t driver, uint8_t * iphead);
net_address_t net_raw_iphead_target_addr(net_raw_driver_t driver, uint8_t * iphead);

net_address_t net_address_from_lwip(net_raw_driver_t driver, uint8_t is_v6, ipX_addr_t * addr, uint16_t port);

void net_address_to_lwip_ipv4(ip_addr_t * addr, net_address_t address);

#endif
