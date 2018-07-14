#include <assert.h>
#include "cpe/utils/stream_buffer.h"
#include "net_address.h"
#include "net_raw_utils.h"

void net_raw_print_raw_data(write_stream_t ws, uint8_t * ethhead, uint8_t * iphead, uint8_t * data) {
    if (iphead == NULL && ethhead) {
    }

    if (data == NULL && iphead) {
        data = iphead + 20;
    }

    if (ethhead) {
        stream_printf(
            ws,
            "MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            ethhead[6]&0xFF, ethhead[7]&0xFF, ethhead[8]&0xFF, ethhead[9]&0xFF, ethhead[10]&0xFF, ethhead[11]&0xFF,
            ethhead[0]&0xFF, ethhead[1]&0xFF, ethhead[2]&0xFF,ethhead[3]&0xFF, ethhead[4]&0xFF, ethhead[5]&0xFF);
    }

    if (iphead) {
        stream_printf(
            ws, "IP: %d.%d.%d.%d => %d.%d.%d.%d\n",
            iphead[12]&0XFF, iphead[13]&0XFF, iphead[14]&0XFF, iphead[15]&0XFF,
            iphead[16]&0XFF, iphead[17]&0XFF, iphead[18]&0XFF, iphead[19]&0XFF);

        uint8_t proto = iphead[9];
        switch(proto) {
        case IPPROTO_ICMP:
            stream_printf(ws, "Protocol: ICMP");
            break;
        case IPPROTO_IGMP:
            stream_printf(ws, "Protocol: IGMP");
            break;
        case IPPROTO_IPIP:
            stream_printf(ws, "Protocol: IPIP");
            break;
        case IPPROTO_TCP:
            stream_printf(
                ws, "Protocol: TCP, source port: %u, dest port: %u",
                ((data[0]<<8)&0XFF00 | data[1]&0XFF),
                ((data[2]<<8)&0XFF00 | data[3]&0XFF));
            break;
        case IPPROTO_UDP: 
            stream_printf(
                ws, "Protocol: UDP, source port: %u, dest port: %u",
                ((data[0]<<8)&0XFF00 | data[1]&0XFF),
                ((data[2]<<8)&0XFF00 | data[3]&0XFF));
            break;
        case IPPROTO_RAW:
            stream_printf(ws, "Protocol: RAW");
            break;
        default:
            stream_printf(ws, "Protocol: Unkown, please query in include/linux/in.h");
            break;
        }
    }
}

const char * net_raw_dump_raw_data(mem_buffer_t buffer, uint8_t * ethhead, uint8_t * iphead, uint8_t * data) {
    struct write_stream_buffer stream = CPE_WRITE_STREAM_BUFFER_INITIALIZER(buffer);

    mem_buffer_clear_data(buffer);
    
    net_raw_print_raw_data((write_stream_t)&stream, ethhead, iphead, data);
    stream_putc((write_stream_t)&stream, 0);
    
    return mem_buffer_make_continuous(buffer, 0);
}

net_address_t net_raw_iphead_source_addr(net_raw_driver_t driver, uint8_t * iphead) {
    struct net_address_data_ipv4 addr_data;
    addr_data.u8[0] = iphead[12];
    addr_data.u8[1] = iphead[13];
    addr_data.u8[2] = iphead[14];
    addr_data.u8[3] = iphead[15];

    uint16_t port =  (((uint16_t)iphead[20])<<8) | iphead[21];
    return net_address_create_from_data_ipv4(net_raw_driver_schedule(driver), &addr_data, port);
}

net_address_t net_raw_iphead_target_addr(net_raw_driver_t driver, uint8_t * iphead) {
    struct net_address_data_ipv4 addr_data;
    addr_data.u8[0] = iphead[16];
    addr_data.u8[1] = iphead[17];
    addr_data.u8[2] = iphead[18];
    addr_data.u8[3] = iphead[19];

    uint16_t port =  (((uint16_t)iphead[22])<<8) | iphead[23];
    return net_address_create_from_data_ipv4(net_raw_driver_schedule(driver), &addr_data, port);
}

net_address_t net_address_from_lwip_ip4(net_raw_driver_t driver, ip_addr_t * addr, uint16_t port) {
    struct net_address_data_ipv4 addr_data;
    addr_data.u8[0] = ip4_addr1(addr);
    addr_data.u8[1] = ip4_addr2(addr);
    addr_data.u8[2] = ip4_addr3(addr);
    addr_data.u8[3] = ip4_addr4(addr);
    return net_address_create_from_data_ipv4(net_raw_driver_schedule(driver), &addr_data, port);
}

net_address_t net_address_from_lwip_ip6(net_raw_driver_t driver, ip6_addr_t * addr, uint16_t port) {
    struct net_address_data_ipv6 addr_data;
    return net_address_create_from_data_ipv6(net_raw_driver_schedule(driver), &addr_data, port);
}

net_address_t net_address_from_lwip(net_raw_driver_t driver, uint8_t is_ipv6, ipX_addr_t * addr, uint16_t port) {
    if (is_ipv6) {
        return net_address_from_lwip_ip6(driver, &addr->ip6, port);
    }
    else {
        return net_address_from_lwip_ip4(driver, &addr->ip4, port);
    }
}

void net_address_to_lwip_ipv4(ip_addr_t * addr, net_address_t address) {
    assert(net_address_type(address) == net_address_ipv4);
    
    struct net_address_data_ipv4 const * addr_data = net_address_data(address);
    IP4_ADDR(addr, addr_data->u8[0], addr_data->u8[1], addr_data->u8[2], addr_data->u8[3]);
}
