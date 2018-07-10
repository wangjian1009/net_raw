#include "net_raw_device_raw_capture_i.h"

net_raw_device_raw_capture_t
net_raw_device_raw_capture_create(
    net_raw_device_raw_t raw, net_raw_device_raw_capture_protocol_t proto, net_address_t source, net_address_t target)
{
    net_raw_driver_t driver = raw->m_device.m_driver;

    if (driver->m_mode != net_raw_driver_match_white) {
        CPE_ERROR(driver->m_em, "raw: device raw capture: musen`t create in white mode");
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
    raw_capture->m_fd = -1;

    TAILQ_INSERT_TAIL(&raw->m_captures, raw_capture, m_next);
    
    return raw_capture;
}

void net_raw_device_raw_capture_free(net_raw_device_raw_capture_t raw_capture) {
    net_raw_device_raw_t raw = raw_capture->m_device;
    net_raw_driver_t driver = raw->m_device.m_driver;

    TAILQ_REMOVE(&raw->m_captures, raw_capture, m_next);

    raw_capture->m_device = (net_raw_device_raw_t)driver;
    TAILQ_INSERT_TAIL(&driver->m_free_device_raw_captures, raw_capture, m_next);
}

void net_raw_device_raw_capture_real_free(net_raw_device_raw_capture_t raw_capture) {
    net_raw_driver_t driver = (net_raw_driver_t)raw_capture->m_device;
    TAILQ_REMOVE(&driver->m_free_device_raw_captures, raw_capture, m_next);
    mem_free(driver->m_alloc, raw_capture);
}
