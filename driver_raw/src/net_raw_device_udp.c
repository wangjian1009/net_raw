
/* void net_raw_device_(void *unused, BAddr local_addr, BAddr remote_addr, const uint8_t *data, int data_len) { */
/*     /\* assert(options.udpgw_remote_server_addr); *\/ */
/*     /\* assert(local_addr.type == BADDR_TYPE_IPV4 || local_addr.type == BADDR_TYPE_IPV6) *\/ */
/*     /\* ASSERT(local_addr.type == remote_addr.type) *\/ */
/*     /\* ASSERT(data_len >= 0) *\/ */

/*     int packet_length = 0; */

/*     switch (local_addr.type) { */
/*         case BADDR_TYPE_IPV4: { */
/* #ifdef __ANDROID__ */
/*             BLog(BLOG_INFO, "UDP: from udprelay %d bytes", data_len); */
/* #else */
/*             BLog(BLOG_INFO, "UDP: from udpgw %d bytes", data_len); */
/* #endif */

/*             if (data_len > UINT16_MAX - (sizeof(struct ipv4_header) + sizeof(struct udp_header)) || */
/*                 data_len > BTap_GetMTU(&device) - (int)(sizeof(struct ipv4_header) + sizeof(struct udp_header)) */
/*             ) { */
/*                 BLog(BLOG_ERROR, "UDP: packet is too large"); */
/*                 return; */
/*             } */

/*             // build IP header */
/*             struct ipv4_header iph; */
/*             iph.version4_ihl4 = IPV4_MAKE_VERSION_IHL(sizeof(iph)); */
/*             iph.ds = hton8(0); */
/*             iph.total_length = hton16(sizeof(iph) + sizeof(struct udp_header) + data_len); */
/*             iph.identification = hton16(0); */
/*             iph.flags3_fragmentoffset13 = hton16(0); */
/*             iph.ttl = hton8(64); */
/*             iph.protocol = hton8(IPV4_PROTOCOL_UDP); */
/*             iph.checksum = hton16(0); */
/*             iph.source_address = remote_addr.ipv4.ip; */
/*             iph.destination_address = local_addr.ipv4.ip; */
/*             iph.checksum = ipv4_checksum(&iph, NULL, 0); */

/*             // build UDP header */
/*             struct udp_header udph; */
/*             udph.source_port = remote_addr.ipv4.port; */
/*             udph.dest_port = local_addr.ipv4.port; */
/*             udph.length = hton16(sizeof(udph) + data_len); */
/*             udph.checksum = hton16(0); */
/*             udph.checksum = udp_checksum(&udph, data, data_len, iph.source_address, iph.destination_address); */

/*             // write packet */
/*             memcpy(device_write_buf, &iph, sizeof(iph)); */
/*             memcpy(device_write_buf + sizeof(iph), &udph, sizeof(udph)); */
/*             memcpy(device_write_buf + sizeof(iph) + sizeof(udph), data, data_len); */
/*             packet_length = sizeof(iph) + sizeof(udph) + data_len; */
/*         } break; */

/*         case BADDR_TYPE_IPV6: { */
/* #ifdef __ANDROID__ */
/*             BLog(BLOG_INFO, "UDP/IPv6: from udprelay %d bytes", data_len); */
/* #else */
/*             BLog(BLOG_INFO, "UDP/IPv6: from udpgw %d bytes", data_len); */
/* #endif */

/*             if (!options.netif_ip6addr) { */
/* #ifdef __ANDROID__ */
/*                 BLog(BLOG_ERROR, "got IPv6 packet from udprelay but IPv6 is disabled"); */
/* #else */
/*                 BLog(BLOG_ERROR, "got IPv6 packet from udpgw but IPv6 is disabled"); */
/* #endif */
/*                 return; */
/*             } */

/*             if (data_len > UINT16_MAX - sizeof(struct udp_header) || */
/*                 data_len > BTap_GetMTU(&device) - (int)(sizeof(struct ipv6_header) + sizeof(struct udp_header)) */
/*             ) { */
/*                 BLog(BLOG_ERROR, "UDP/IPv6: packet is too large"); */
/*                 return; */
/*             } */

/*             // build IPv6 header */
/*             struct ipv6_header iph; */
/*             iph.version4_tc4 = hton8((6 << 4)); */
/*             iph.tc4_fl4 = hton8(0); */
/*             iph.fl = hton16(0); */
/*             iph.payload_length = hton16(sizeof(struct udp_header) + data_len); */
/*             iph.next_header = hton8(IPV6_NEXT_UDP); */
/*             iph.hop_limit = hton8(64); */
/*             memcpy(iph.source_address, remote_addr.ipv6.ip, 16); */
/*             memcpy(iph.destination_address, local_addr.ipv6.ip, 16); */

/*             // build UDP header */
/*             struct udp_header udph; */
/*             udph.source_port = remote_addr.ipv6.port; */
/*             udph.dest_port = local_addr.ipv6.port; */
/*             udph.length = hton16(sizeof(udph) + data_len); */
/*             udph.checksum = hton16(0); */
/*             udph.checksum = udp_ip6_checksum(&udph, data, data_len, iph.source_address, iph.destination_address); */

/*             // write packet */
/*             memcpy(device_write_buf, &iph, sizeof(iph)); */
/*             memcpy(device_write_buf + sizeof(iph), &udph, sizeof(udph)); */
/*             memcpy(device_write_buf + sizeof(iph) + sizeof(udph), data, data_len); */
/*             packet_length = sizeof(iph) + sizeof(udph) + data_len; */
/*         } break; */
/*     } */

/*     // submit packet */
/*     BTap_Send(&device, device_write_buf, packet_length); */
/* } */
