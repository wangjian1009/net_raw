#include "assert.h"
#include "cpe/pal/pal_socket.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/utils_sock/sock_utils.h"
#include "net_endpoint.h"
#include "net_address.h"
#include "net_driver.h"
#include "net_raw_endpoint.h"

static err_t net_raw_endpoint_recv_func(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void net_raw_endpoint_err_func(void *arg, err_t err);
static err_t net_raw_endpoint_poll_func(void *arg, struct tcp_pcb *pcb);
static int net_raw_endpoint_do_write(struct net_raw_endpoint * endpoint);

void net_raw_endpoint_set_pcb(struct net_raw_endpoint * endpoint, struct tcp_pcb * pcb) {
    if (endpoint->m_pcb) {
        tcp_err(endpoint->m_pcb, NULL);
        tcp_recv(endpoint->m_pcb, NULL);
        tcp_sent(endpoint->m_pcb, NULL);
        tcp_poll(endpoint->m_pcb, NULL, 0);

        err_t err = tcp_close(endpoint->m_pcb);
        if (err != ERR_OK) {
            net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
            net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
        
            CPE_ERROR(
                driver->m_em, "raw: %s: tcp close failed (%d)",
                net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint),
                err);
            tcp_abort(endpoint->m_pcb);
        }
        endpoint->m_pcb = NULL;
    }

    endpoint->m_pcb = pcb;

    if (endpoint->m_pcb) {
        tcp_nagle_disable(endpoint->m_pcb);
        tcp_arg(endpoint->m_pcb, endpoint);
        tcp_err(endpoint->m_pcb, net_raw_endpoint_err_func);
        tcp_recv(endpoint->m_pcb, net_raw_endpoint_recv_func);
        tcp_poll(endpoint->m_pcb, net_raw_endpoint_poll_func, 4);
    }
}

static err_t net_raw_endpoint_recv_func(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    net_raw_endpoint_t endpoint = arg;
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
    net_schedule_t schedule = net_endpoint_schedule(base_endpoint);
    
    assert(err == ERR_OK); /* checked in lwIP source. Otherwise, I've no idea what should
                              be done with the pbuf in case of an error.*/

    if (!p) {
        if (driver->m_debug >= 2) {
            CPE_INFO(
                driver->m_em, "raw: %s: client closed",
                net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint),
                err);
        }

        if (net_endpoint_set_state(base_endpoint, net_endpoint_state_network_error) != 0) {
            net_endpoint_free(base_endpoint);
            return ERR_ABRT;
        }
        else {
            return ERR_OK;
        }
    }

    assert(p->tot_len > 0);

    uint32_t size = p->tot_len;
    void * data = net_endpoint_rbuf_alloc(base_endpoint, &size);
    if (data == NULL) {
        CPE_ERROR(
            driver->m_em, "raw: %s: no buffer for data, size=%d",
            net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint),
            data);
        return ERR_MEM;
    }

    if (net_endpoint_rbuf_supply(base_endpoint, size) != 0) {
        if (net_endpoint_set_state(base_endpoint, net_endpoint_state_logic_error) != 0) {
            if (driver->m_debug || net_schedule_debug(schedule) >= 2) {
                CPE_INFO(
                    driver->m_em, "raw: %s: free for process fail!",
                    net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
            }
            net_endpoint_free(base_endpoint);
        }
    }

    pbuf_free(p);

    return ERR_OK;
}

static void net_raw_endpoint_err_func(void *arg, err_t err) {
    net_raw_endpoint_t endpoint = arg;
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    if (driver->m_debug) {
        CPE_INFO(
            driver->m_em, "raw: %s: client error (%d)",
            net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint),
            (int)err);
    }
}

static err_t net_raw_endpoint_poll_func(void *arg, struct tcp_pcb *pcb) {
    net_raw_endpoint_t endpoint = arg;

    /* if (conn->state == NETCONN_WRITE) { */
    /*     lwip_netconn_do_writemore(conn); */
    /* } */
    /* else if (conn->state == NETCONN_CLOSE) { */
    /*     lwip_netconn_do_close_internal(conn); */
    /* } */

    /* /\* Did a nonblocking write fail before? Then check available write-space. *\/ */
    /* if (conn->flags & NETCONN_FLAG_CHECK_WRITESPACE) { */
    /*     /\* If the queued byte- or pbuf-count drops below the configured low-water limit, */
    /*        let select mark this pcb as writable again. *\/ */
    /*     if ((conn->pcb.tcp != NULL) && (tcp_sndbuf(conn->pcb.tcp) > TCP_SNDLOWAT) && */
    /*         (tcp_sndqueuelen(conn->pcb.tcp) < TCP_SNDQUEUELOWAT)) { */
    /*         conn->flags &= ~NETCONN_FLAG_CHECK_WRITESPACE; */
    /*         API_EVENT(conn, NETCONN_EVT_SENDPLUS, 0); */
    /*     } */
    /* } */

    return ERR_OK;
}

int net_raw_endpoint_init(net_endpoint_t base_endpoint) {
    net_raw_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    endpoint->m_pcb = NULL;
    return 0;
}

void net_raw_endpoint_fini(net_endpoint_t base_endpoint) {
    net_raw_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    if (endpoint->m_pcb) {
        net_raw_endpoint_set_pcb(endpoint, NULL);
        assert(endpoint->m_pcb == NULL);
    }
}

int net_raw_endpoint_on_output(net_endpoint_t base_endpoint) {
    if (net_endpoint_state(base_endpoint) != net_endpoint_state_established) return 0;

    net_raw_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    if (endpoint->m_pcb == NULL) {
        CPE_ERROR(
            driver->m_em, "raw: %s: on output: not connected!",
            net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint));
        return -1;
    }

    return net_raw_endpoint_do_write(endpoint);
}

static int net_raw_endpoint_do_write(struct net_raw_endpoint * endpoint) {
    /*err_t err = tcp_write(endpoint->m_pcb, const void *dataptr, u16_t len, 0);*/
    return 0;
}

int net_raw_endpoint_connect(net_endpoint_t base_endpoint) {
    net_raw_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
    net_schedule_t schedule = net_endpoint_schedule(base_endpoint);
    error_monitor_t em = net_schedule_em(schedule);

    if (endpoint->m_pcb == NULL) {
        CPE_ERROR(
            em, "raw: %s: already connected!",
            net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
        return -1;
    }

    net_address_t remote_addr = net_endpoint_remote_address(base_endpoint);
    if (remote_addr == NULL) {
        CPE_ERROR(
            em, "raw: %s: connect with no remote address!",
            net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
        return -1;
    }

    uint8_t is_ipv6 = 0;
    
    net_address_t local_address = net_endpoint_address(base_endpoint);
    if (local_address) {
        switch(net_address_type(local_address)) {
        case net_address_ipv4:
            is_ipv6 = 0;
            break;
        case net_address_ipv6:
            is_ipv6 = 1;
            break;
        case net_address_domain:
            CPE_ERROR(
                em, "raw: %s: connect not support domain address!",
                net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
            return -1;
        }
    }
    else {
        switch(net_address_type(remote_addr)) {
        case net_address_ipv4:
            is_ipv6 = 0;
            break;
        case net_address_ipv6:
            is_ipv6 = 1;
            break;
        case net_address_domain:
            CPE_ERROR(
                em, "raw: %s: connect not support domain address!",
                net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
            return -1;
        }
    }

    /* if (is_ipv6) { */
    /* } */
    /* else { */
        
    /*     if (endpoint->m_fd == -1) { */
    /*         CPE_ERROR( */
    /*             em, "raw: %s: create socket fail, errno=%d (%s)", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         return -1; */
    /*     } */

    /*     struct sockaddr_storage addr; */
    /*     socklen_t addr_len = sizeof(addr); */
    /*     if (net_address_to_sockaddr(local_address, (struct sockaddr *)&addr, &addr_len) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "raw: %s: connect not support connect to domain address!", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*         return -1; */
    /*     } */

    /*     if(cpe_bind(endpoint->m_fd, (struct sockaddr *)&addr, addr_len) != 0) { */
    /*         CPE_ERROR( */
    /*             em, "raw: %s: bind fail, errno=%d (%s)", */
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
    /*             em, "raw: %s: create ipv4 socket fail, errno=%d (%s)", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), */
    /*             cpe_sock_errno(), cpe_sock_errstr(cpe_sock_errno())); */
    /*         return -1; */
    /*     } */
    /* } */

    /* if (cpe_sock_set_none_block(endpoint->m_fd, 1) != 0) { */
    /*     CPE_ERROR( */
    /*         em, "raw: %s: set non-block fail, errno=%d (%s)", */
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
    /*             em, "raw: %s: sock process fail", */
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
    /*                 em, "raw: %s: connect start", */
    /*                 net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*         } */

    /*         assert(!ev_is_active(&endpoint->m_watcher)); */
    /*         ev_io_init( */
    /*             &endpoint->m_watcher, */
    /*             net_raw_endpoint_connect_cb, endpoint->m_fd, */
    /*             EV_READ | EV_WRITE); */
    /*         ev_io_start(driver->m_ev_loop, &endpoint->m_watcher); */
            
    /*         return net_endpoint_set_state(base_endpoint, net_endpoint_state_connecting); */
    /*     } */
    /*     else { */
    /*         CPE_ERROR( */
    /*             em, "raw: %s: connect error, errno=%d (%s)", */
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
    /*             em, "raw: %s: connect success", */
    /*             net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint)); */
    /*     } */

    /*     if (net_endpoint_address(base_endpoint) == NULL) { */
    /*         net_raw_endpoint_update_local_address(endpoint); */
    /*     } */

    /*     return net_endpoint_set_state(base_endpoint, net_endpoint_state_established); */
    /* } */
    return 0;
}

void net_raw_endpoint_close(net_endpoint_t base_endpoint) {
    net_raw_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    if (endpoint->m_pcb == NULL) return;

    net_raw_endpoint_set_pcb(endpoint, NULL);

    if (driver->m_debug >= 2) {
        CPE_INFO(
            driver->m_em, "raw: %s: tcp closed",
            net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint));
    }
}
