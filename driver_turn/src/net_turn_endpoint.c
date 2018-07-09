#include "assert.h"
#include "cpe/pal/pal_socket.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/utils_sock/sock_utils.h"
#include "net_endpoint.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_turn_endpoint.h"

int net_turn_endpoint_init(net_endpoint_t base_endpoint) {
    //net_turn_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    
    return 0;
}

void net_turn_endpoint_fini(net_endpoint_t base_endpoint) {
    /* net_turn_endpoint_t endpoint = net_endpoint_data(base_endpoint); */
    /* net_turn_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint)); */
}

int net_turn_endpoint_on_output(net_endpoint_t base_endpoint) {
    if (net_endpoint_state(base_endpoint) != net_endpoint_state_established) return 0;

    /* net_turn_endpoint_t endpoint = net_endpoint_data(base_endpoint); */
    /* net_turn_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint)); */
    return 0;
}

int net_turn_endpoint_connect(net_endpoint_t base_endpoint) {
    /* net_turn_endpoint_t endpoint = net_endpoint_data(base_endpoint); */
    /* net_turn_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint)); */
    /* net_schedule_t schedule = net_endpoint_schedule(base_endpoint); */
    /* error_monitor_t em = net_schedule_em(schedule); */

    /* if (endpoint->m_fd != -1) { */
    /*     CPE_ERROR( */
    /*         em, "turn: %s: already connected!", */
    /*         net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*     return -1; */
    /* } */

    /* net_address_t remote_addr = net_endpoint_remote_address(base_endpoint); */
    /* if (remote_addr == NULL) { */
    /*     CPE_ERROR( */
    /*         em, "turn: %s: connect with no remote address!", */
    /*         net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*     return -1; */
    /* } */
        
    /* net_address_t local_address = net_endpoint_address(base_endpoint); */
    /* if (local_address) { */
    /*     switch(net_address_type(local_address)) { */
    /*     case net_address_ipv4: */
    /*         endpoint->m_fd = cpe_sock_open(AF_INET, SOCK_STREAM, 0); */
    /*         break; */
    /*     case net_address_ipv6: */
    /*         endpoint->m_fd = cpe_sock_open(AF_INET6, SOCK_STREAM, 0); */
    /*         break; */
    /*     case net_address_domain: */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: connect not support domain address!", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*         return -1; */
    /*     } */

    /*     if (endpoint->m_fd == -1) { */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: create socket fail, errno=%d (%s)", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         return -1; */
    /*     } */

    /*     struct sockaddr_storage addr; */
    /*     socklen_t addr_len = sizeof(addr); */
    /*     if (net_address_to_sockaddr(local_address, (struct sockaddr *)&addr, &addr_len) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: connect not support connect to domain address!", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*         return -1; */
    /*     } */

    /*     if(cpe_bind(endpoint->m_fd, (struct sockaddr *)&addr, addr_len) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: bind fail, errno=%d (%s)", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         cpe_sock_close(endpoint->m_fd); */
    /*         endpoint->m_fd = -1; */
    /*         return -1; */
    /*     } */
    /* } */
    /* else { */
    /*     endpoint->m_fd = cpe_sock_open(AF_INET, SOCK_STREAM, 0); */
    /*     if (endpoint->m_fd == -1) { */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: create ipv4 socket fail, errno=%d (%s)", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         return -1; */
    /*     } */
    /* } */

    /* if (cpe_sock_set_none_block(endpoint->m_fd, 1) != 0) { */
    /*     CPE_ERROR( */
    /*         em, "turn: %s: set non-block fail, errno=%d (%s)", */
    /*         net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*         cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*     cpe_sock_close(endpoint->m_fd); */
    /*     endpoint->m_fd = -1; */
    /*     return -1; */
    /* } */

    /* struct sockaddr_storage addr; */
    /* socklen_t addr_len = sizeof(addr); */
    /* net_address_to_sockaddr(remote_addr, (struct sockaddr *)&addr, &addr_len); */

    /* if (driver->m_sock_process_fun) { */
    /*     if (driver->m_sock_process_fun(driver, driver->m_sock_process_ctx, endpoint->m_fd, remote_addr) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: sock process fail", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*         cpe_sock_close(endpoint->m_fd); */
    /*         endpoint->m_fd = -1; */
    /*         return -1; */
    /*     } */
    /* } */
    
    /* if (cpe_connect(endpoint->m_fd, (struct sockaddr *)&addr, addr_len) != 0) { */
    /*     if (cpe_sock_errno() == EINPROGRESS || cpe_sock_errno() == EWOULDBLOCK) { */
    /*         if (net_schedule_debug(schedule) >= 2) { */
    /*             CPE_INFO( */
    /*                 em, "turn: %s: connect start", */
    /*                 net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*         } */

    /*         assert(!ev_is_active(&endpoint->m_watcher)); */
    /*         ev_io_init( */
    /*             &endpoint->m_watcher, */
    /*             net_turn_endpoint_connect_cb, endpoint->m_fd, */
    /*             EV_READ | EV_WRITE); */
    /*         ev_io_start(driver->m_ev_loop, &endpoint->m_watcher); */
            
    /*         return net_endpoint_set_state(base_endpoint, net_endpoint_state_connecting); */
    /*     } */
    /*     else { */
    /*         CPE_ERROR( */
    /*             em, "turn: %s: connect error, errno=%d (%s)", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         cpe_sock_close(endpoint->m_fd); */
    /*         endpoint->m_fd = -1; */
    /*         return -1; */
    /*     } */
    /* } */
    /* else { */
    /*     if (driver->m_debug || net_schedule_debug(schedule) >= 2) { */
    /*         CPE_INFO( */
    /*             em, "turn: %s: connect success", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*     } */

    /*     if (net_endpoint_address(base_endpoint) == NULL) { */
    /*         net_turn_endpoint_update_local_address(endpoint); */
    /*     } */

    /*     return net_endpoint_set_state(base_endpoint, net_endpoint_state_established); */
    /* } */
}

void net_turn_endpoint_close(net_endpoint_t base_endpoint) {
    /* net_turn_endpoint_t endpoint = net_endpoint_data(base_endpoint); */
    /* net_turn_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint)); */
}
