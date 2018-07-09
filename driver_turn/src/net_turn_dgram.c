#include "assert.h"
#include "cpe/pal/pal_socket.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/utils_sock/sock_utils.h"
#include "net_dgram.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_turn_dgram.h"

int net_turn_dgram_init(net_dgram_t base_dgram) {
    /* net_schedule_t schedule = net_dgram_schedule(base_dgram); */
    /* error_monitor_t em = net_schedule_em(schedule); */
    /* net_turn_dgram_t dgram = net_dgram_data(base_dgram); */
    /* net_turn_driver_t driver = net_driver_data(net_dgram_driver(base_dgram)); */
    /* net_address_t address = net_dgram_address(base_dgram); */

    /* if (address) { */
    /*     switch(net_address_type(address)) { */
    /*     case net_address_ipv4: */
    /*         dgram->m_fd = cpe_sock_open(AF_INET, SOCK_DGRAM, 0); */
    /*         break; */
    /*     case net_address_ipv6: */
    /*         dgram->m_fd = cpe_sock_open(AF_INET6, SOCK_DGRAM, 0); */
    /*         break; */
    /*     case net_address_domain: */
    /*         CPE_ERROR(em, "turn: dgyam: not support domain address!"); */
    /*         return -1; */
    /*     } */
    /* } */
    /* else { */
    /*     dgram->m_fd = cpe_sock_open(AF_INET, SOCK_DGRAM, 0); */
    /* } */

    /* if (dgram->m_fd == -1) { */
    /*     CPE_ERROR( */
    /*         em, "turn: dgram: socket create error, errno=%d (%s)", */
    /*         cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*     return -1; */
    /* } */

    /* if (driver->m_sock_process_fun) { */
    /*     if (driver->m_sock_process_fun(driver, driver->m_sock_process_ctx, dgram->m_fd, NULL) != 0) { */
    /*         CPE_ERROR(em, "turn: dgram: sock process fail"); */
    /*         cpe_sock_close(dgram->m_fd); */
    /*         return -1; */
    /*     } */
    /* } */
    
    /* if (address) { */
    /*     struct sockaddr_storage addr; */
    /*     socklen_t addr_len = sizeof(addr); */

    /*     if (net_address_to_sockaddr(address, (struct sockaddr *)&addr, &addr_len) != 0) { */
    /*         CPE_ERROR(em, "turn: dgram: get sockaddr from address fail"); */
    /*         cpe_sock_close(dgram->m_fd); */
    /*         return -1; */
    /*     } */

    /*     sock_set_reuseport(dgram->m_fd); */

    /*     if (cpe_bind(dgram->m_fd, (struct sockaddr *)&addr, addr_len) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "turn: dgram: bind addr fail, errno=%d (%s)", */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         cpe_sock_close(dgram->m_fd); */
    /*         dgram->m_fd = -1; */
    /*         return -1; */
    /*     } */

    /*     if (driver->m_debug || net_schedule_debug(schedule) >= 2) { */
    /*         CPE_INFO( */
    /*             em, "turn: dgram: bind to %s", */
    /*             net_address_dump(net_schedule_tmp_buffer(schedule), address)); */
    /*     } */
    /* } */
    /* else { */
    /*     struct sockaddr_storage addr; */
    /*     socklen_t addr_len = sizeof(struct sockaddr_storage); */
    /*     memset(&addr, 0, addr_len); */
    /*     if (getsockname(dgram->m_fd, (struct sockaddr *)&addr, &addr_len) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "turn: dgram: sockaddr error, errno=%d (%s)", */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         cpe_sock_close(dgram->m_fd); */
    /*         dgram->m_fd = -1; */
    /*         return -1; */
    /*     } */

    /*     address = net_address_create_from_sockaddr(schedule, (struct sockaddr *)&addr, addr_len); */
    /*     if (address == NULL) { */
    /*         CPE_ERROR(net_schedule_em(schedule), "turn: dgram: create address fail"); */
    /*         cpe_sock_close(dgram->m_fd); */
    /*         dgram->m_fd = -1; */
    /*         return -1; */
    /*     } */

    /*     if (driver->m_debug || net_schedule_debug(schedule) >= 2) { */
    /*         CPE_INFO( */
    /*             em, "turn: dgram: auto bind at %s", */
    /*             net_address_dump(net_schedule_tmp_buffer(schedule), address)); */
    /*     } */

    /*     net_dgram_set_address(base_dgram, address); */
    /* } */
    
    return 0;
}

void net_turn_dgram_fini(net_dgram_t base_dgram) {
    /* net_turn_dgram_t dgram = net_dgram_data(base_dgram); */
    /* net_turn_driver_t driver = net_driver_data(net_dgram_driver(base_dgram)); */
}

int net_turn_dgram_send(net_dgram_t base_dgram, net_address_t target, void const * data, size_t data_len) {
    printf("xxxxx: send %d\n", data_len);
    return data_len;
}
