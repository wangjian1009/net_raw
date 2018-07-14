#include "net_address.h"
#include "net_raw_device_tun_listener_i.h"

net_raw_device_tun_listener_t
net_raw_device_tun_listener_create(net_raw_device_tun_t device_tun, net_address_t address, net_protocol_t protocol) {
    net_raw_driver_t driver = device_tun->m_device.m_driver;
    net_schedule_t schedule = net_raw_driver_schedule(driver);

    net_raw_device_tun_listener_t tun_listener = TAILQ_FIRST(&driver->m_free_device_tun_listeners);
    if (tun_listener) {
        TAILQ_REMOVE(&driver->m_free_device_tun_listeners, tun_listener, m_next);
    }
    else {
        tun_listener = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_tun_listener));
        if (tun_listener == NULL) {
            CPE_ERROR(driver->m_em, "raw: device tun listener: alloc fail");
            return NULL;
        }
    }

    tun_listener->m_device = device_tun;
    tun_listener->m_address = NULL;
    tun_listener->m_protocol = protocol;

    tun_listener->m_address = net_address_copy(schedule, address);
    if (tun_listener->m_address == NULL) {
        CPE_ERROR(driver->m_em, "raw: device tun listener: dup address fail");
        tun_listener->m_device = (net_raw_device_tun_t)driver;
        TAILQ_INSERT_TAIL(&driver->m_free_device_tun_listeners, tun_listener, m_next);
        return NULL;
    }

    cpe_hash_entry_init(&tun_listener->m_hh);

    if (cpe_hash_table_insert_unique(&device_tun->m_listeners, tun_listener) != 0) {
        CPE_ERROR(
            driver->m_em, "raw: device tun listener: address %s duplicate",
            net_address_dump(net_schedule_tmp_buffer(schedule), address));
        net_address_free(tun_listener->m_address);
        tun_listener->m_device = (net_raw_device_tun_t)driver;
        TAILQ_INSERT_TAIL(&driver->m_free_device_tun_listeners, tun_listener, m_next);
        return NULL;
    }
    
    return tun_listener;
}

void net_raw_device_tun_listener_free(net_raw_device_tun_listener_t tun_listener) {
    net_raw_driver_t driver = tun_listener->m_device->m_device.m_driver;

    cpe_hash_table_remove_by_ins(&tun_listener->m_device->m_listeners, tun_listener);
    
    net_address_free(tun_listener->m_address);
    tun_listener->m_device = (net_raw_device_tun_t)driver;
    
    TAILQ_INSERT_TAIL(&driver->m_free_device_tun_listeners, tun_listener, m_next);
}

void net_raw_device_tun_listener_free_all(net_raw_device_tun_t device_tun) {
    struct cpe_hash_it tun_listener_it;
    net_raw_device_tun_listener_t tun_listener;

    cpe_hash_it_init(&tun_listener_it, &device_tun->m_listeners);

    tun_listener = cpe_hash_it_next(&tun_listener_it);
    while(tun_listener) {
        net_raw_device_tun_listener_t next = cpe_hash_it_next(&tun_listener_it);
        net_raw_device_tun_listener_free(tun_listener);
        tun_listener = next;
    }
}

void net_raw_device_tun_listener_real_free(net_raw_device_tun_listener_t tun_listener) {
    net_raw_driver_t driver = (net_raw_driver_t)tun_listener->m_device;
    TAILQ_REMOVE(&driver->m_free_device_tun_listeners, tun_listener, m_next);
    mem_free(driver->m_alloc, tun_listener);
}

net_raw_device_tun_listener_t
net_raw_device_tun_listener_find(net_raw_device_tun_t tun, net_address_t address) {
    struct net_raw_device_tun_listener key;
    key.m_address = address;
    return cpe_hash_table_find(&tun->m_listeners, &key);
}

uint32_t net_raw_device_tun_listener_hash(net_raw_device_tun_listener_t listener, void * user_data) {
    return net_address_hash(listener->m_address);
}

int net_raw_device_tun_listener_eq(net_raw_device_tun_listener_t l, net_raw_device_tun_listener_t r, void * user_data) {
    return net_address_cmp(l->m_address, r->m_address) == 0 ? 1 : 0;
}

