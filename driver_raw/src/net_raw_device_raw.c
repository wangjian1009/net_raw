#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#if CPE_OS_LINUX    
#include <linux/if_ether.h>
#endif
#include "cpe/pal/pal_socket.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_unistd.h"
#include "net_raw_device_raw_i.h"
#include "net_raw_device_raw_capture_i.h"
#include "net_raw_utils.h"

static void net_raw_device_raw_rw_cb(EV_P_ ev_io *w, int revents);
static int net_raw_device_raw_send(net_raw_device_t device, uint8_t *data, int data_len);
static void net_raw_device_raw_fini(net_raw_device_t device);

static struct net_raw_device_type s_device_type_raw = {
    "raw",
    net_raw_device_raw_send,
    net_raw_device_raw_fini,
};

net_raw_device_raw_t net_raw_device_raw_create(net_raw_driver_t driver, uint8_t capture_all) {
    net_raw_device_raw_t device_raw = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_raw));
    if (device_raw == NULL) {
        CPE_ERROR(driver->m_em, "raw: device alloc fail!");
        return NULL;
    }

    device_raw->m_fd = -1;
    device_raw->m_capture_all = capture_all;
    TAILQ_INIT(&device_raw->m_captures);

    if (net_raw_device_init(&device_raw->m_device, driver, &s_device_type_raw, NULL, NULL, 0) != 0) {
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }

    if (cpe_hash_table_init(
            &device_raw->m_captures_by_source,
            driver->m_alloc,
            (cpe_hash_fun_t) net_raw_device_raw_source_hash,
            (cpe_hash_eq_t) net_raw_device_raw_source_eq,
            CPE_HASH_OBJ2ENTRY(net_raw_device_raw_capture, m_hh_for_source),
            -1) != 0)
    {
        net_raw_device_fini(&device_raw->m_device);
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }

    if (cpe_hash_table_init(
            &device_raw->m_captures_by_target,
            driver->m_alloc,
            (cpe_hash_fun_t) net_raw_device_raw_target_hash,
            (cpe_hash_eq_t) net_raw_device_raw_target_eq,
            CPE_HASH_OBJ2ENTRY(net_raw_device_raw_capture, m_hh_for_target),
            -1) != 0)
    {
        cpe_hash_table_fini(&device_raw->m_captures_by_source);
        net_raw_device_fini(&device_raw->m_device);
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }
    
    if (device_raw->m_capture_all) {
        device_raw->m_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (device_raw->m_fd == -1) {
            CPE_ERROR(driver->m_em, "raw: device raw: create raw socket fail, %d %s",  errno, strerror(errno));
            cpe_hash_table_fini(&device_raw->m_captures_by_target);
            cpe_hash_table_fini(&device_raw->m_captures_by_source);
            net_raw_device_fini(&device_raw->m_device);
            mem_free(driver->m_alloc, device_raw);
            return NULL;
        }

        if (device_raw->m_fd < 0) {
            CPE_ERROR(driver->m_em, "raw: device raw: not support rawsocket!");
            cpe_hash_table_fini(&device_raw->m_captures_by_target);
            cpe_hash_table_fini(&device_raw->m_captures_by_source);
            net_raw_device_fini(&device_raw->m_device);
            mem_free(driver->m_alloc, device_raw);
            return NULL;
        }
    
        if (fcntl(device_raw->m_fd, F_SETFL, O_NONBLOCK) < 0) {
            CPE_ERROR(driver->m_em, "raw: device raw: set nonblock fail, %d %s",  errno, strerror(errno));
            close(device_raw->m_fd);
            cpe_hash_table_fini(&device_raw->m_captures_by_target);
            cpe_hash_table_fini(&device_raw->m_captures_by_source);
            net_raw_device_fini(&device_raw->m_device);
            mem_free(driver->m_alloc, device_raw);
            return NULL;
        }
    
        device_raw->m_watcher.data = device_raw;
        ev_io_init(&device_raw->m_watcher, net_raw_device_raw_rw_cb, device_raw->m_fd, EV_READ);
        ev_io_start(driver->m_ev_loop, &device_raw->m_watcher);
    }
    
    return device_raw;
}

net_raw_device_raw_t net_raw_device_raw_cast(net_raw_device_t device) {
    return device->m_type == &s_device_type_raw ? (net_raw_device_raw_t)device : NULL;
}

static void net_raw_device_raw_rw_cb(EV_P_ ev_io *w, int revents) {
    net_raw_device_raw_t device_raw = w->data;
    net_raw_driver_t driver = device_raw->m_device.m_driver;

    if (revents & EV_READ) {
        char buffer[2048];
        int n_read = recvfrom(device_raw->m_fd, buffer, sizeof(buffer), 0, NULL, NULL);
        /*
          14   6(dest)+6(source)+2(type or length)
          +
          20   ip header 
          +
          8   icmp,tcp or udp header
          = 42
        */
        if(n_read < 28) {
            CPE_ERROR(driver->m_em, "raw: device raw: Incomplete header, packet corrupt/n");
            return;
        }

        uint8_t * ethhead = NULL;
        uint8_t * iphead = buffer;  
        uint8_t * data = iphead + 20;

        uint8_t proto = iphead[9];
        if (proto != IPPROTO_TCP) {
            if (driver->m_debug >= 3) {
                CPE_INFO(driver->m_em, "raw: device raw: %s", net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), ethhead, iphead, data));
            }
            return;
        }
        
        net_address_t source_addr = net_raw_iphead_source_addr(driver, iphead);
        if (source_addr == NULL) {
            CPE_ERROR(driver->m_em, "raw: device raw: read source addr fail");
            return;
        }
        
        net_address_t target_addr = net_raw_iphead_target_addr(driver, iphead);
        if (target_addr == NULL) {
            CPE_ERROR(driver->m_em, "raw: device raw: read target addr fail");
            net_address_free(source_addr);
            return;
        }

        CPE_ERROR(driver->m_em, "   package: source=%s", net_address_dump(net_raw_driver_tmp_buffer(driver), source_addr));
        CPE_ERROR(driver->m_em, "            target=%s", net_address_dump(net_raw_driver_tmp_buffer(driver), target_addr));
        
        if (net_raw_device_raw_capture_find_by_target(device_raw, target_addr) != NULL
            || net_raw_device_raw_capture_find_by_source(device_raw, source_addr) != NULL)
        {
        }

        net_address_free(target_addr);
        net_address_free(source_addr);
        
        //CPE_INFO(driver->m_em, "raw: device raw: %s", net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), ethhead, iphead, data));
        
        /* switch(proto) { */
        /* case IPPROTO_TCP: */
        /* case IPPROTO_UDP:  */
        /*     break; */
        /* default: */
        /*     /\* if (driver->m_debug >= 2) { *\/ */
        /*         CPE_INFO(driver->m_em, "raw: device raw: %s", net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), ethhead, iphead, data)); */
        /*     /\* } *\/ */
        /* } */
    }
}

static int net_raw_device_raw_send(net_raw_device_t device, uint8_t *data, int data_len) {
    return 0;
}

static void net_raw_device_raw_fini(net_raw_device_t device) {
    net_raw_device_raw_t device_raw = (net_raw_device_raw_t)device;
    net_raw_driver_t driver = device_raw->m_device.m_driver;

    if (device_raw->m_fd != -1) {
        close(device_raw->m_fd);
        device_raw->m_fd = -1;
        ev_io_stop(driver->m_ev_loop, &device_raw->m_watcher);
    }

    while(!TAILQ_EMPTY(&device_raw->m_captures)) {
        net_raw_device_raw_capture_free(TAILQ_FIRST(&device_raw->m_captures));
    }

    cpe_hash_table_fini(&device_raw->m_captures_by_source);
    cpe_hash_table_fini(&device_raw->m_captures_by_target);
}
