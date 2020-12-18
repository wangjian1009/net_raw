#include <assert.h>
#include "cpe/pal/pal_socket.h"
#include "cpe/utils/stream_buffer.h"
#include "net_address.h"
#include "net_tun_utils.h"

static const char * s_tcp_flags[] = { "FIN", "SYN", "RST", "PSH", "ACK", "URG" };

void net_tun_print_raw_data(write_stream_t ws, uint8_t const * ethhead, uint8_t const * iphead, uint8_t const * data) {
    if (iphead == NULL && ethhead) {
    }

    if (data == NULL && iphead) {
        data = iphead + TCP_HLEN;
    }

    if (iphead == NULL) return;

    char mac_from[32];
    char mac_to[32];
    if (ethhead) {
        snprintf(
            mac_from, sizeof(mac_from), "(%.2X:%02X:%02X:%02X:%02X:%02X)",
            ethhead[6]&0xFF, ethhead[7]&0xFF, ethhead[8]&0xFF, ethhead[9]&0xFF, ethhead[10]&0xFF, ethhead[11]&0xFF);
        snprintf(
            mac_to, sizeof(mac_to), "(%.2X:%02X:%02X:%02X:%02X:%02X)",
            ethhead[0]&0xFF, ethhead[1]&0xFF, ethhead[2]&0xFF,ethhead[3]&0xFF, ethhead[4]&0xFF, ethhead[5]&0xFF);
    }
    else {
        mac_from[0] = 0;
        mac_to[0] = 0;
    }
    
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
        uint16_t port_from = ((((uint16_t)data[0])<<8) & 0XFF00) | (((uint16_t)data[1]) & 0XFF);
        uint16_t port_to = ((((uint16_t)data[2])<<8) & 0XFF00) | (((uint16_t)data[3]) & 0XFF);
        if (ethhead) {
            stream_printf(
                ws, "TCP: %s:%d(%s) ==> %s:%d(%s)",
                ip_from, port_from, mac_from, ip_to, port_to, mac_to);
        }
        else {
            stream_printf(ws, "TCP: %s:%d ==> %s:%d", ip_from, port_from, ip_to, port_to);
        }

        uint16_t tcp_head_len = (uint16_t)data[12];
        tcp_head_len = (tcp_head_len >> 4) * sizeof(uint32_t);
        uint32_t sn;
        CPE_COPY_NTOH32(&sn, data + 4);
        uint32_t ack;
        CPE_COPY_NTOH32(&ack, data + 8);
        stream_printf(ws, " head-len=%d, sn=" FMT_UINT32_T ", ack=" FMT_UINT32_T, (int)tcp_head_len, sn, ack);

        uint8_t flag = data[13];
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
        
        break;
    }
    case IPPROTO_UDP: {
        uint16_t port_from = ((((uint16_t)data[0])<<8) & 0XFF00) | (((uint16_t)data[1]) & 0XFF);
        uint16_t port_to = ((((uint16_t)data[2])<<8) & 0XFF00) | (((uint16_t)data[3]) & 0XFF);
        if (ethhead) {
            stream_printf(ws, "UDP: %s:%d(%s) ==> %s:%d(%s)", ip_from, port_from, mac_from, ip_to, port_to, mac_to);
        }
        else {
            stream_printf(ws, "UDP: %s:%d ==> %s:%d", ip_from, port_from, ip_to, port_to);
        }
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
    if (ethhead) {
        stream_printf(ws, "%s: %s(%s) ==> %s(%s)", protocol, ip_from, mac_from, ip_to, mac_to);
    }
    else {
        stream_printf(ws, "%s: %s ==> %s", protocol, ip_from, ip_to);
    }
}

const char * net_tun_dump_raw_data(mem_buffer_t buffer, uint8_t const * ethhead, uint8_t const * iphead, uint8_t const * data) {
    struct write_stream_buffer stream = CPE_WRITE_STREAM_BUFFER_INITIALIZER(buffer);

    mem_buffer_clear_data(buffer);
    
    net_tun_print_raw_data((write_stream_t)&stream, ethhead, iphead, data);
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
