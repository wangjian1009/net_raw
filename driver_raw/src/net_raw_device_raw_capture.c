#include <fcntl.h>
#include <sys/ioctl.h>
#include "cpe/pal/pal_string.h"
#include "net_address.h"
#include "net_raw_device_raw_capture_i.h"
#include "net_raw_utils.h"

static void net_raw_device_raw_capture_on_read(net_raw_device_raw_capture_t raw_capture);

#if NET_RAW_USE_EV
static void net_raw_device_raw_capture_rw_cb(EV_P_ ev_io *w, int revents);
#endif

#if NET_RAW_USE_DQ
static void net_raw_device_raw_capture_start_r(net_raw_device_raw_capture_t raw_capture);
static void net_raw_device_raw_capture_stop_r(net_raw_device_raw_capture_t raw_capture);
#endif

net_raw_device_raw_capture_t
net_raw_device_raw_capture_create(
    net_raw_device_raw_t raw, net_address_t source, net_address_t target)
{
    net_raw_driver_t driver = raw->m_device.m_driver;
    net_schedule_t schedule = net_raw_driver_schedule(driver);

    if (source == NULL && target == NULL) {
        CPE_ERROR(driver->m_em, "raw: device raw capture: no source address or target address");
        return NULL;
    }

    net_raw_device_raw_capture_t raw_capture = TAILQ_FIRST(&driver->m_free_device_raw_captures);
    if (raw_capture) {
        TAILQ_REMOVE(&driver->m_free_device_raw_captures, raw_capture, m_next);
    }
    else {
        raw_capture = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_raw_capture));
        if (raw_capture == NULL) {
            CPE_ERROR(driver->m_em, "raw: device raw capture: alloc fail");
            return NULL;
        }
    }

    raw_capture->m_device = raw;
    raw_capture->m_source_address = NULL;
    raw_capture->m_target_address = NULL;
    raw_capture->m_fd = -1;
#if NET_RAW_USE_DQ
    raw_capture->m_source_r = NULL;
#endif

    if (source) {
        raw_capture->m_source_address = net_address_copy(schedule, source);
        if (raw_capture->m_source_address == NULL) {
            CPE_ERROR(driver->m_em, "raw: device raw capture: dup source address fail");
            goto create_error;
        }
    }

    if (target) {
        raw_capture->m_target_address = net_address_copy(schedule, target);
        if (raw_capture->m_target_address == NULL) {
            CPE_ERROR(driver->m_em, "raw: device raw capture: dup target address fail");
            goto create_error;
        }
    }

    if (!raw->m_capture_all) {
        raw_capture->m_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (raw_capture->m_fd < 0) {
            CPE_ERROR(driver->m_em, "raw: device raw: not support rawsocket!");
            goto create_error;
        }
    
        if (fcntl(raw_capture->m_fd, F_SETFL, O_NONBLOCK) < 0) {
            CPE_ERROR(driver->m_em, "raw: device raw: set nonblock fail, %d %s",  errno, strerror(errno));
            goto create_error;
        }

        if (raw_capture->m_source_address) {
            struct sockaddr_storage addr;
            socklen_t addr_len = sizeof(addr);
            if (net_address_to_sockaddr(raw_capture->m_source_address, (struct sockaddr *)&addr, &addr_len) != 0) {
                CPE_ERROR(driver->m_em, "raw: device raw: get source addr fail");
                goto create_error;
            }
            if (connect(raw_capture->m_fd, (struct sockaddr *)&addr, addr_len) == -1) {
                CPE_ERROR(
                    driver->m_em, "raw: device raw: connect to %s fail",
                    net_address_dump(net_raw_driver_tmp_buffer(driver), raw_capture->m_source_address));
                goto create_error;
            }

            cpe_hash_entry_init(&raw_capture->m_hh_for_source);
            cpe_hash_table_insert(&raw->m_captures_by_source, raw_capture);
        }

        if (raw_capture->m_target_address) {
            struct sockaddr_storage addr;
            socklen_t addr_len = sizeof(addr);
            if (net_address_to_sockaddr(raw_capture->m_target_address, (struct sockaddr *)&addr, &addr_len) != 0) {
                CPE_ERROR(driver->m_em, "raw: device raw: get target addr fail");
                goto create_error;
            }
            if (bind(raw_capture->m_fd, (struct sockaddr *)&addr, addr_len) == -1) {
                CPE_ERROR(
                    driver->m_em, "raw: device raw: connect to %s fail, %d (%s)",
                    net_address_dump(net_raw_driver_tmp_buffer(driver), raw_capture->m_target_address),
                    errno, strerror(errno));
                goto create_error;
            }

            cpe_hash_entry_init(&raw_capture->m_hh_for_target);
            cpe_hash_table_insert(&raw->m_captures_by_target, raw_capture);
        }

#if NET_RAW_USE_EV
        raw_capture->m_watcher.data = raw_capture;
        ev_io_init(&raw_capture->m_watcher, net_raw_device_raw_capture_rw_cb, raw_capture->m_fd, EV_READ);
        ev_io_start(driver->m_ev_loop, &raw_capture->m_watcher);
#endif

#if NET_RAW_USE_DQ
        net_raw_device_raw_capture_start_r(raw_capture);
#endif
    }
    
    TAILQ_INSERT_TAIL(&raw->m_captures, raw_capture, m_next);

    if (driver->m_debug >= 2) {
        if (raw_capture->m_target_address) {
            if (raw_capture->m_source_address) {
            }
            else {
            }
        }
        else {
            if (raw_capture->m_source_address) {
            }
        }
    }
    
    return raw_capture;

create_error:
    if (raw_capture->m_fd != -1) {
        close(raw_capture->m_fd);
    }
    
    if (raw_capture->m_target_address) {
        cpe_hash_table_remove_by_ins(&raw->m_captures_by_target, raw_capture);
        net_address_free(raw_capture->m_target_address);
    }

    if (raw_capture->m_source_address) {
        cpe_hash_table_remove_by_ins(&raw->m_captures_by_source, raw_capture);
        net_address_free(raw_capture->m_source_address);
    }
    
    raw_capture->m_device = (net_raw_device_raw_t)driver;
    TAILQ_INSERT_TAIL(&driver->m_free_device_raw_captures, raw_capture, m_next);

    return NULL;
}

void net_raw_device_raw_capture_free(net_raw_device_raw_capture_t raw_capture) {
    net_raw_device_raw_t raw = raw_capture->m_device;
    net_raw_driver_t driver = raw->m_device.m_driver;

    if (raw_capture->m_fd != -1) {
        close(raw_capture->m_fd);
        raw_capture->m_fd = -1;
#if NET_RAW_USE_EV
        ev_io_stop(driver->m_ev_loop, &raw_capture->m_watcher);
#endif
#if NET_RAW_USE_DQ
        net_raw_device_raw_capture_stop_r(raw_capture);
#endif
    }

    if (raw_capture->m_target_address) {
        cpe_hash_table_remove_by_ins(&raw->m_captures_by_target, raw_capture);
        net_address_free(raw_capture->m_target_address);
    }

    if (raw_capture->m_source_address) {
        cpe_hash_table_remove_by_ins(&raw->m_captures_by_source, raw_capture);
        net_address_free(raw_capture->m_source_address);
    }
    
    TAILQ_REMOVE(&raw->m_captures, raw_capture, m_next);

    raw_capture->m_device = (net_raw_device_raw_t)driver;
    TAILQ_INSERT_TAIL(&driver->m_free_device_raw_captures, raw_capture, m_next);
}

void net_raw_device_raw_capture_real_free(net_raw_device_raw_capture_t raw_capture) {
    net_raw_driver_t driver = (net_raw_driver_t)raw_capture->m_device;
    TAILQ_REMOVE(&driver->m_free_device_raw_captures, raw_capture, m_next);
    mem_free(driver->m_alloc, raw_capture);
}

static void net_raw_device_raw_capture_on_read(net_raw_device_raw_capture_t raw_capture) {
    net_raw_device_raw_t device_raw = raw_capture->m_device;
    net_raw_driver_t driver = device_raw->m_device.m_driver;

    uint8_t buffer[2048];
    struct sockaddr_storage from_addr;
    socklen_t from_addr_len = sizeof(from_addr);
    ssize_t n_read = recvfrom(raw_capture->m_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_addr_len);
    /*
      20   ip header 
      +
      8   icmp,tcp or udp header
      = 28
    */
    if(n_read < 28) {
        CPE_ERROR(driver->m_em, "raw: device raw: capture: Incomplete header, packet corrupt");
        return;
    }

    uint8_t * iphead = buffer;  
    uint8_t * data = iphead + 20;
        
    uint8_t proto = iphead[9];
    switch(proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP: 
        break;
    default:
        if (driver->m_debug >= 2) {
            CPE_ERROR(
                driver->m_em, "raw: device raw: capture: %s",
                net_raw_dump_raw_data(net_raw_driver_tmp_buffer(driver), NULL, iphead, data));
        }
    }
}

net_raw_device_raw_capture_t net_raw_device_raw_capture_find_by_source(net_raw_device_raw_t raw, net_address_t source) {
    struct net_raw_device_raw_capture key;
    key.m_source_address = source;
    return cpe_hash_table_find(&raw->m_captures_by_source, &key);
}

net_raw_device_raw_capture_t net_raw_device_raw_capture_find_by_target(net_raw_device_raw_t raw, net_address_t target) {
    struct net_raw_device_raw_capture key;
    key.m_target_address = target;
    return cpe_hash_table_find(&raw->m_captures_by_target, &key);
}

uint32_t net_raw_device_raw_source_hash(net_raw_device_raw_capture_t capture, void * user_data) {
    return net_address_hash(capture->m_source_address);
}

int net_raw_device_raw_source_eq(net_raw_device_raw_capture_t l, net_raw_device_raw_capture_t r, void * user_data) {
    return net_address_cmp(l->m_source_address, r->m_source_address) == 0 ? 1 : 0;
}

uint32_t net_raw_device_raw_target_hash(net_raw_device_raw_capture_t capture, void * user_data) {
    return net_address_hash(capture->m_target_address);
}

int net_raw_device_raw_target_eq(net_raw_device_raw_capture_t l, net_raw_device_raw_capture_t r, void * user_data) {
    return net_address_cmp(l->m_target_address, r->m_target_address) == 0 ? 1 : 0;
}

#if NET_RAW_USE_EV
static void net_raw_device_raw_capture_rw_cb(EV_P_ ev_io *w, int revents) {
    if (revents & EV_READ) {
        net_raw_device_raw_capture_on_read(w->data);
    }
}
#endif

#if NET_RAW_USE_DQ
static void net_raw_device_raw_capture_start_r(net_raw_device_raw_capture_t raw_capture) {
    if (raw_capture->m_source_r == NULL) {
        raw_capture->m_source_r = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, raw_capture->m_fd, 0, dispatch_get_main_queue());
        dispatch_retain(raw_capture->m_source_r);
        dispatch_source_set_event_handler(raw_capture->m_source_r, ^{ net_raw_device_raw_capture_on_read(raw_capture); });
        dispatch_resume(raw_capture->m_source_r);
    }
}

static void net_raw_device_raw_capture_stop_r(net_raw_device_raw_capture_t raw_capture) {
    if (raw_capture->m_source_r) {
        dispatch_source_set_event_handler(raw_capture->m_source_r, NULL);
        dispatch_source_cancel(raw_capture->m_source_r);
        dispatch_release(raw_capture->m_source_r);
        raw_capture->m_source_r = NULL;
    }
}

#endif
