#include "net_address.h"
#include "net_raw_device_listener_i.h"

net_raw_device_listener_t
net_raw_device_listener_create(net_raw_device_t device, net_address_t address, net_protocol_t protocol) {
    net_raw_driver_t driver = device->m_driver;
    net_schedule_t schedule = net_raw_driver_schedule(driver);

    net_raw_device_listener_t listener = TAILQ_FIRST(&driver->m_free_device_listeners);
    if (listener) {
        TAILQ_REMOVE(&driver->m_free_device_listeners, listener, m_next);
    }
    else {
        listener = mem_alloc(driver->m_alloc, sizeof(struct net_raw_device_listener));
        if (listener == NULL) {
            CPE_ERROR(driver->m_em, "raw: device tun listener: alloc fail");
            return NULL;
        }
    }

    listener->m_device = device;
    listener->m_address = NULL;
    listener->m_protocol = protocol;

    listener->m_address = net_address_copy(schedule, address);
    if (listener->m_address == NULL) {
        CPE_ERROR(driver->m_em, "raw: device tun listener: dup address fail");
        listener->m_device = (net_raw_device_t)driver;
        TAILQ_INSERT_TAIL(&driver->m_free_device_listeners, listener, m_next);
        return NULL;
    }

    cpe_hash_entry_init(&listener->m_hh);

    if (cpe_hash_table_insert_unique(&device->m_listeners, listener) != 0) {
        CPE_ERROR(
            driver->m_em, "raw: device tun listener: address %s duplicate",
            net_address_dump(net_schedule_tmp_buffer(schedule), address));
        net_address_free(listener->m_address);
        listener->m_device = (net_raw_device_t)driver;
        TAILQ_INSERT_TAIL(&driver->m_free_device_listeners, listener, m_next);
        return NULL;
    }
    
    return listener;
}

void net_raw_device_listener_free(net_raw_device_listener_t listener) {
    net_raw_driver_t driver = listener->m_device->m_driver;

    cpe_hash_table_remove_by_ins(&listener->m_device->m_listeners, listener);
    
    net_address_free(listener->m_address);
    listener->m_device = (net_raw_device_t)driver;
    
    TAILQ_INSERT_TAIL(&driver->m_free_device_listeners, listener, m_next);
}

void net_raw_device_listener_free_all(net_raw_device_t device) {
    struct cpe_hash_it listener_it;
    net_raw_device_listener_t listener;

    cpe_hash_it_init(&listener_it, &device->m_listeners);

    listener = cpe_hash_it_next(&listener_it);
    while(listener) {
        net_raw_device_listener_t next = cpe_hash_it_next(&listener_it);
        net_raw_device_listener_free(listener);
        listener = next;
    }
}

void net_raw_device_listener_real_free(net_raw_device_listener_t listener) {
    net_raw_driver_t driver = (net_raw_driver_t)listener->m_device;
    TAILQ_REMOVE(&driver->m_free_device_listeners, listener, m_next);
    mem_free(driver->m_alloc, listener);
}

net_raw_device_listener_t
net_raw_device_listener_find(net_raw_device_t tun, net_address_t address) {
    struct net_raw_device_listener key;
    key.m_address = address;
    return cpe_hash_table_find(&tun->m_listeners, &key);
}

uint32_t net_raw_device_listener_hash(net_raw_device_listener_t listener, void * user_data) {
    return net_address_hash(listener->m_address);
}

int net_raw_device_listener_eq(net_raw_device_listener_t l, net_raw_device_listener_t r, void * user_data) {
    return net_address_cmp(l->m_address, r->m_address) == 0 ? 1 : 0;
}

