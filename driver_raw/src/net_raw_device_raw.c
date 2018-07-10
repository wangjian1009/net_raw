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

static void net_raw_device_raw_rw_cb(EV_P_ ev_io *w, int revents);
static int net_raw_device_raw_send(net_raw_device_t device, uint8_t *data, int data_len);
static void net_raw_device_raw_fini(net_raw_device_t device);

static struct net_raw_device_type s_device_type_raw = {
    "raw",
    net_raw_device_raw_send,
    net_raw_device_raw_fini,
};

net_raw_device_raw_t net_raw_device_raw_create(net_raw_driver_t driver) {
    net_raw_device_raw_t device_raw = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_raw));
    if (device_raw == NULL) {
        CPE_ERROR(driver->m_em, "raw: device alloc fail!");
        return NULL;
    }

    device_raw->m_fd = -1;
    
    if (net_raw_device_init(&device_raw->m_device, driver, &s_device_type_raw, NULL, NULL) != 0) {
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }

#if CPE_OS_LINUX    
    device_raw->m_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (device_raw->m_fd == -1) {
        CPE_ERROR(driver->m_em, "raw: device raw: create raw socket fail, %d %s",  errno, strerror(errno));
        net_raw_device_fini(&device_raw->m_device);
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }
#endif

    if (device_raw->m_fd < 0) {
        CPE_ERROR(driver->m_em, "raw: device raw: not support rawsocket!");
        net_raw_device_fini(&device_raw->m_device);
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }
    
    if (fcntl(device_raw->m_fd, F_SETFL, O_NONBLOCK) < 0) {
        CPE_ERROR(driver->m_em, "raw: device raw: set nonblock fail, %d %s",  errno, strerror(errno));
        close(device_raw->m_fd);
        net_raw_device_fini(&device_raw->m_device);
        mem_free(driver->m_alloc, device_raw);
        return NULL;
    }
    
    device_raw->m_watcher.data = device_raw;
    ev_io_init(&device_raw->m_watcher, net_raw_device_raw_rw_cb, device_raw->m_fd, EV_READ);
    ev_io_start(driver->m_ev_loop, &device_raw->m_watcher);
    
    return device_raw;
}

static void net_raw_device_raw_rw_cb(EV_P_ ev_io *w, int revents) {
}

static int net_raw_device_raw_send(net_raw_device_t device, uint8_t *data, int data_len) {
    return 0;
}

static void net_raw_device_raw_fini(net_raw_device_t device) {
}
