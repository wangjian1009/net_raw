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

static void net_raw_device_raw_dump_raw_data(net_raw_driver_t driver, char * ethhead, char * iphead, char * daata);

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

    if (driver->m_mode == net_raw_driver_match_black) {
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
    }
    
    if (driver->m_debug) {
        CPE_INFO(driver->m_em, "raw: device raw created");
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
        if(n_read < 42) {
            CPE_ERROR(driver->m_em, "Incomplete header, packet corrupt/n");
            return;
        }

        char * ethhead = buffer;
        char * iphead = ethhead + 14;  
        char * data = iphead + 20;
        
        uint8_t proto = iphead[9];
        switch(proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP: 
            break;
        default:
            if (driver->m_debug >= 2) {
                
            }
        }
    }
}

static int net_raw_device_raw_send(net_raw_device_t device, uint8_t *data, int data_len) {
    return 0;
}

static void net_raw_device_raw_fini(net_raw_device_t device) {
    
}

static void net_raw_device_raw_dump_raw_data(net_raw_driver_t driver, char * ethhead, char * iphead, char * data) {
    CPE_INFO(
        driver->m_em,
        "MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
        ethhead[6]&0xFF, ethhead[7]&0xFF, ethhead[8]&0xFF, ethhead[9]&0xFF, ethhead[10]&0xFF, ethhead[11]&0xFF,
        ethhead[0]&0xFF, ethhead[1]&0xFF, ethhead[2]&0xFF,ethhead[3]&0xFF, ethhead[4]&0xFF, ethhead[5]&0xFF);

    CPE_INFO(
        driver->m_em, "IP: %d.%d.%d.%d => %d.%d.%d.%d",
        iphead[12]&0XFF, iphead[13]&0XFF, iphead[14]&0XFF, iphead[15]&0XFF,
        iphead[16]&0XFF, iphead[17]&0XFF, iphead[18]&0XFF, iphead[19]&0XFF);

    uint8_t proto = iphead[9];
    switch(proto) {
    case IPPROTO_ICMP:
        CPE_INFO(driver->m_em, "Protocol: ICMP");
        break;
    case IPPROTO_IGMP:
        CPE_INFO(driver->m_em, "Protocol: IGMP");
        break;
    case IPPROTO_IPIP:
        CPE_INFO(driver->m_em, "Protocol: IPIP");
        break;
    case IPPROTO_TCP:
        CPE_INFO(
            driver->m_em, "Protocol: TCP, source port: %u, dest port: %u",
            ((data[0]<<8)&0XFF00 | data[1]&0XFF),
            ((data[2]<<8)&0XFF00 | data[3]&0XFF));
        break;
    case IPPROTO_UDP: 
        CPE_INFO(
            driver->m_em, "Protocol: UDP, source port: %u, dest port: %u",
            ((data[0]<<8)&0XFF00 | data[1]&0XFF),
            ((data[2]<<8)&0XFF00 | data[3]&0XFF));
        break;
    case IPPROTO_RAW:
        CPE_INFO(driver->m_em, "Protocol: RAW");
        break;
    default:
        CPE_INFO(driver->m_em, "Protocol: Unkown, please query in include/linux/in.h");
        break;
    }
}
                                      
