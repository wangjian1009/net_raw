#include <assert.h>
#include "cpe/pal/pal_socket.h"
#include "cpe/utils/stream_buffer.h"
#include "net_address.h"
#include "net_tun_utils.h"

static const char * s_tcp_flags[] = { "FIN", "SYN", "RST", "PSH", "ACK", "URG" };

void net_tun_print_raw_data(write_stream_t ws, uint8_t const * iphead, uint32_t packet_size, uint8_t dump_content) {
    assert(iphead);

    uint8_t iphlen = (iphead[0]&0X0F) * sizeof(uint32_t);
    if (iphlen > packet_size) {
        stream_printf(ws, "too small data, iphlen=" FMT_UINT32_T ", packet-size" FMT_UINT32_T, iphlen, packet_size);
        return;
    }
    
    uint8_t const * ipdata = iphead + iphlen;
    uint32_t ipdata_len = packet_size - iphlen;

    char ip_from[32];
    char ip_to[32];
    snprintf(ip_from, sizeof(ip_from), "%d.%d.%d.%d", iphead[12]&0XFF, iphead[13]&0XFF, iphead[14]&0XFF, iphead[15]&0XFF);
    snprintf(ip_to, sizeof(ip_to), "%d.%d.%d.%d", iphead[16]&0XFF, iphead[17]&0XFF, iphead[18]&0XFF, iphead[19]&0XFF);

    const char * protocol = NULL;

    uint8_t proto = iphead[9];
    switch(proto) {
    case IPPROTO_ICMP:
        protocol = "ICMP";
        goto print_with_protocol;
    case IPPROTO_IGMP:
        protocol = "IGMP";
        goto print_with_protocol;
#if defined IPPROTO_IPIP
    case IPPROTO_IPIP:
        protocol = "IPIP";
        goto print_with_protocol;
#endif
    case IPPROTO_TCP: {
        uint16_t port_from = ((((uint16_t)ipdata[0])<<8) & 0XFF00) | (((uint16_t)ipdata[1]) & 0XFF);
        uint16_t port_to = ((((uint16_t)ipdata[2])<<8) & 0XFF00) | (((uint16_t)ipdata[3]) & 0XFF);
        stream_printf(ws, "TCP: %s:%d ==> %s:%d", ip_from, port_from, ip_to, port_to);

        uint16_t tcp_head_len = (uint16_t)ipdata[12];
        tcp_head_len = (tcp_head_len >> 4) * sizeof(uint32_t);
        uint32_t sn;
        CPE_COPY_NTOH32(&sn, ipdata + 4);
        uint32_t ack;
        CPE_COPY_NTOH32(&ack, ipdata + 8);
        stream_printf(ws, " head-len=%d, sn=" FMT_UINT32_T ", ack=" FMT_UINT32_T, (int)tcp_head_len, sn, ack);

        uint8_t flag = ipdata[13];
        stream_printf(ws, ", flags=(");
        uint8_t i;
        uint8_t flag_count = 0;
        for(i = 0; i < CPE_ARRAY_SIZE(s_tcp_flags); ++i) {
            if (flag & (((uint8_t)0x1) << i)) {
                if (flag_count++ != 0) { stream_printf(ws, ", "); }
                stream_printf(ws, "%s", s_tcp_flags[i]);
            }
        }
        stream_printf(ws, ")");

        if (dump_content && ipdata_len > tcp_head_len) {
            stream_printf(ws, "\n");
            stream_dump_data(ws, ipdata + tcp_head_len, ipdata_len - tcp_head_len, 0);
        }
        break;
    }
    case IPPROTO_UDP: {
        uint16_t port_from = ((((uint16_t)ipdata[0])<<8) & 0XFF00) | (((uint16_t)ipdata[1]) & 0XFF);
        uint16_t port_to = ((((uint16_t)ipdata[2])<<8) & 0XFF00) | (((uint16_t)ipdata[3]) & 0XFF);
        stream_printf(ws, "UDP: %s:%d ==> %s:%d", ip_from, port_from, ip_to, port_to);
        break;
    }
    case IPPROTO_RAW:
        protocol = "RAW";
        goto print_with_protocol;
    default:
        stream_printf(ws, "protocol %d unkown, please query in include/linux/in.h", proto);
        break;
    }

    return;
    
print_with_protocol:
    stream_printf(ws, "%s: %s ==> %s", protocol, ip_from, ip_to);
}

const char * net_tun_dump_raw_data(
    mem_buffer_t buffer, uint8_t const * iphead, uint32_t data_size, uint8_t dump_content)
{
    struct write_stream_buffer stream = CPE_WRITE_STREAM_BUFFER_INITIALIZER(buffer);

    mem_buffer_clear_data(buffer);
    
    net_tun_print_raw_data((write_stream_t)&stream, iphead, data_size, dump_content);
    stream_putc((write_stream_t)&stream, 0);
    
    return mem_buffer_make_continuous(buffer, 0);
}

net_address_t net_tun_iphead_source_addr(net_tun_driver_t driver, uint8_t const * iphead) {
    struct net_address_data_ipv4 addr_data;
    addr_data.u8[0] = iphead[12];
    addr_data.u8[1] = iphead[13];
    addr_data.u8[2] = iphead[14];
    addr_data.u8[3] = iphead[15];

    uint16_t port =  (((uint16_t)iphead[20])<<8) | iphead[21];
    return net_address_create_ipv4_from_data(net_tun_driver_schedule(driver), &addr_data, port);
}

net_address_t net_tun_iphead_target_addr(net_tun_driver_t driver, uint8_t const * iphead) {
    struct net_address_data_ipv4 addr_data;
    addr_data.u8[0] = iphead[16];
    addr_data.u8[1] = iphead[17];
    addr_data.u8[2] = iphead[18];
    addr_data.u8[3] = iphead[19];

    uint16_t port =  (((uint16_t)iphead[22])<<8) | iphead[23];
    return net_address_create_ipv4_from_data(net_tun_driver_schedule(driver), &addr_data, port);
}

net_address_t net_address_from_lwip_ip4(net_tun_driver_t driver, const ip4_addr_t * addr, uint16_t port) {
    struct net_address_data_ipv4 addr_data;
    addr_data.u8[0] = ip4_addr1(addr);
    addr_data.u8[1] = ip4_addr2(addr);
    addr_data.u8[2] = ip4_addr3(addr);
    addr_data.u8[3] = ip4_addr4(addr);
    return net_address_create_ipv4_from_data(net_tun_driver_schedule(driver), &addr_data, port);
}

net_address_t net_address_from_lwip_ip6(net_tun_driver_t driver, const ip6_addr_t * addr, uint16_t port) {
    struct net_address_data_ipv6 addr_data;
    return net_address_create_ipv6_from_data(net_tun_driver_schedule(driver), &addr_data, port);
}

net_address_t net_address_from_lwip(net_tun_driver_t driver, const ip_addr_t * addr, uint16_t port) {
    if (addr->type == IPADDR_TYPE_V6) {
        return net_address_from_lwip_ip6(driver, &addr->u_addr.ip6, port);
    }
    else {
        assert(addr->type == IPADDR_TYPE_V4);
        return net_address_from_lwip_ip4(driver, &addr->u_addr.ip4, port);
    }
}

void net_address_to_lwip_ipv4(ip4_addr_t * addr, net_address_t address) {
    assert(net_address_type(address) == net_address_ipv4);
    
    struct net_address_data_ipv4 const * addr_data = net_address_data(address);
    IP4_ADDR(addr, addr_data->u8[0], addr_data->u8[1], addr_data->u8[2], addr_data->u8[3]);
}

void net_address_to_lwip_ipv6(ip6_addr_t * addr, net_address_t address) {
    assert(net_address_type(address) == net_address_ipv6);
    
    struct net_address_data_ipv6 const * addr_data = net_address_data(address);
    addr->addr[0] = addr_data->u32[0];
    addr->addr[1] = addr_data->u32[1];
    addr->addr[2] = addr_data->u32[2];
    addr->addr[3] = addr_data->u32[3];
}
