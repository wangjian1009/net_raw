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
static err_t net_raw_endpoint_sent_func(void *arg, struct tcp_pcb *tpcb, u16_t len);
static void net_raw_endpoint_err_func(void *arg, err_t err);
static err_t net_raw_endpoint_poll_func(void *arg, struct tcp_pcb *pcb);
static err_t net_raw_endpoint_connected_func(void *arg, struct tcp_pcb *tpcb, err_t err);
static int net_raw_endpoint_do_write(struct net_raw_endpoint * endpoint);

void net_raw_endpoint_set_pcb(struct net_raw_endpoint * endpoint, struct tcp_pcb * pcb) {
    if (endpoint->m_pcb) {
        tcp_err(endpoint->m_pcb, NULL);
        tcp_recv(endpoint->m_pcb, NULL);
        tcp_sent(endpoint->m_pcb, NULL);
        tcp_poll(endpoint->m_pcb, NULL, 0);

        printf("xxxxx fini 1\n");
        
        err_t err = tcp_close(endpoint->m_pcb);
        if (err != ERR_OK) {
            printf("xxxxx fini 2\n");
            net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
            net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
        
            CPE_ERROR(
                driver->m_em, "raw: %s: tcp close failed (%d)",
                net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint),
                err);
            printf("xxxxx fini 3\n");
            tcp_abort(endpoint->m_pcb);
            printf("xxxxx fini 4\n");
        }
        endpoint->m_pcb = NULL;
    }

    endpoint->m_pcb = pcb;

    if (endpoint->m_pcb) {
        tcp_nagle_disable(endpoint->m_pcb);
        tcp_arg(endpoint->m_pcb, endpoint);
        tcp_err(endpoint->m_pcb, net_raw_endpoint_err_func);
        tcp_recv(endpoint->m_pcb, net_raw_endpoint_recv_func);
        tcp_sent(endpoint->m_pcb, net_raw_endpoint_sent_func);
        tcp_poll(endpoint->m_pcb, net_raw_endpoint_poll_func, 4);
    }
}

static err_t net_raw_endpoint_recv_func(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    net_raw_endpoint_t endpoint = arg;
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
    net_schedule_t schedule = net_endpoint_schedule(base_endpoint);

    CPE_INFO(driver->m_em, "xxxxx: recv");

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

static err_t net_raw_endpoint_sent_func(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    net_raw_endpoint_t endpoint = arg;
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    CPE_INFO(driver->m_em, "xxxxx: send %d", len);
    
    if (net_raw_endpoint_do_write(endpoint) != 0) {
        if (net_endpoint_set_state(base_endpoint, net_endpoint_state_network_error) != 0) {
            net_endpoint_free(base_endpoint);
            return ERR_ABRT; 
        }
    }

    return ERR_OK;
}

static void net_raw_endpoint_err_func(void *arg, err_t err) {
    net_raw_endpoint_t endpoint = arg;
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    if (driver->m_debug) {
        CPE_INFO(
            driver->m_em, "raw: %s: client error %d (%s)",
            net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint),
            (int)err, lwip_strerr(err));
    }

    if (err != ERR_ABRT) {
        net_raw_endpoint_set_pcb(endpoint, NULL);
    }
    else {
        endpoint->m_pcb = NULL;
    }

    if (net_endpoint_set_state(base_endpoint, net_endpoint_state_network_error) != 0) {
        net_endpoint_free(base_endpoint);
    }
}

static err_t net_raw_endpoint_poll_func(void *arg, struct tcp_pcb *pcb) {
    /* net_raw_endpoint_t endpoint = arg; */
    /* net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint); */
    /* net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint)); */

    /* CPE_INFO( */
    /*     driver->m_em, "raw: %s: poll", */
    /*     net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint)); */
    
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

static err_t net_raw_endpoint_connected_func(void *arg, struct tcp_pcb *tpcb, err_t err) {
    net_raw_endpoint_t endpoint = arg;
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
    net_schedule_t schedule = net_endpoint_schedule(base_endpoint);
    error_monitor_t em = net_schedule_em(schedule);

    if (err != ERR_OK) {
        CPE_ERROR(
            em, "ev: %s: connect error, errno=%d (%s)",
            net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), err, lwip_strerr(err));
        if (net_endpoint_set_state(base_endpoint, net_endpoint_state_network_error) != 0) {
            net_endpoint_free(base_endpoint);
            return ERR_ABRT;
        }
        return ERR_OK;
    }

    if (driver->m_debug || net_schedule_debug(schedule) >= 2) {
        CPE_INFO(
            em, "ev: %s: connect success",
            net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
    }

    if (net_endpoint_set_state(base_endpoint, net_endpoint_state_established) != 0) {
        net_endpoint_free(base_endpoint);
        return ERR_ABRT;
    }

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
    net_endpoint_t base_endpoint = net_endpoint_from_data(endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));

    while(net_endpoint_state(base_endpoint) == net_endpoint_state_established && !net_endpoint_wbuf_is_empty(base_endpoint)) {
        uint32_t data_size;
        void * data = net_endpoint_wbuf(base_endpoint, &data_size);

        assert(data_size > 0);
        assert(data);

        if (data_size > tcp_sndbuf(endpoint->m_pcb)) {
            data_size = tcp_sndbuf(endpoint->m_pcb);
        }
        
        if (data_size == 0) {
            break;
        }

        err_t err = tcp_write(endpoint->m_pcb, data, data_size, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            if (err == ERR_MEM) {
                break;
            }

            CPE_ERROR(
                driver->m_em, "raw: %s: write: tcp_write fail %d (%s)!",
                net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint), err, lwip_strerr(err));
            
            return -1;
        }

        net_endpoint_wbuf_consume(base_endpoint, data_size);
    }

    err_t err = tcp_output(endpoint->m_pcb);
    if (err != ERR_OK) {
        CPE_ERROR(
            driver->m_em, "raw: %s: write: tcp_output fail %d (%s)!",
            net_endpoint_dump(net_raw_driver_tmp_buffer(driver), base_endpoint), err, lwip_strerr(err));
        return -1;
    }

    return 0;
}

int net_raw_endpoint_connect(net_endpoint_t base_endpoint) {
    net_raw_endpoint_t endpoint = net_endpoint_data(base_endpoint);
    net_raw_driver_t driver = net_driver_data(net_endpoint_driver(base_endpoint));
    net_schedule_t schedule = net_endpoint_schedule(base_endpoint);
    error_monitor_t em = net_schedule_em(schedule);

    if (endpoint->m_pcb != NULL) {
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

    struct tcp_pcb * pcb = NULL;
    if (is_ipv6) {
        CPE_ERROR(
            em, "raw: %s: connect: not support ipv6 yet!",
            net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
        return -1;
    }
    else {
        pcb = tcp_new();
        if (pcb == NULL) {
            CPE_ERROR(
                em, "raw: %s: connect: create pcb fail!",
                net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
            return -1;
        }

        if (local_address) {
            ip_addr_t local_lwip_addr;
            net_address_to_lwip_ipv4(&local_lwip_addr, local_address);

            err_t err = tcp_bind(pcb, &local_lwip_addr, net_address_port(local_address));
            if (err != ERR_OK) {
                CPE_ERROR(
                    em, "raw: %s: bind fail, errno=%d",
                    net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), err);
                tcp_abort(pcb);
                return -1;
            }
        }

        ip_addr_t remote_iwip_addr;
        net_address_to_lwip_ipv4(&remote_iwip_addr, remote_addr);

        err_t err = tcp_connect(pcb, &remote_iwip_addr, net_address_port(remote_addr), net_raw_endpoint_connected_func);
        if (err != ERR_OK) {
            CPE_ERROR(
                em, "raw: %s: connect error, errno=%d",
                net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint), err);
            tcp_abort(pcb);
            return -1;
        }
    }

    if (net_schedule_debug(schedule) >= 2) {
        CPE_INFO(
            em, "raw: %s: connect start",
            net_endpoint_dump(net_schedule_tmp_buffer(schedule), base_endpoint));
    }

    net_raw_endpoint_set_pcb(endpoint, pcb);
    
    return net_endpoint_set_state(base_endpoint, net_endpoint_state_connecting);
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

