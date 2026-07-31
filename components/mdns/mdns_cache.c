/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <strings.h>
#include "esp_log.h"
#include "mdns_cache.h"
#include "mdns_mem_caps.h"
#include "mdns_utils.h"

static const char *TAG = "mdns_cache";

static mdns_cache_entry_t *s_cache;

static inline bool names_equal(const char *a, const char *b)
{
    return !mdns_utils_str_null_or_empty(a) && !mdns_utils_str_null_or_empty(b) && strcasecmp(a, b) == 0;
}

static inline bool nullable_names_equal(const char *a, const char *b)
{
    return (mdns_utils_str_null_or_empty(a) && mdns_utils_str_null_or_empty(b)) || names_equal(a, b);
}

static bool update_ttl(uint32_t *cached_ttl, uint32_t ttl)
{
    uint32_t previous_ttl = *cached_ttl;
    if (*cached_ttl == 0) {
        *cached_ttl = ttl;
    } else {
        *cached_ttl = *cached_ttl < ttl ? *cached_ttl : ttl;
    }

    return previous_ttl != *cached_ttl;
}

static bool service_match(const mdns_service_cache_t *cache, const char *instance, const char *service, const char *proto)
{
    return names_equal(cache->instance_name, instance) && names_equal(cache->service, service) && names_equal(cache->proto, proto);
}

static bool addr_equal(const esp_ip_addr_t *a, const esp_ip_addr_t *b)
{
    if (a->type != b->type) {
        return false;
    }

#ifdef CONFIG_LWIP_IPV6
    if (a->type == ESP_IPADDR_TYPE_V6) {
        return !memcmp(a->u_addr.ip6.addr, b->u_addr.ip6.addr, sizeof(a->u_addr.ip6.addr));
    }
#endif
#ifdef CONFIG_LWIP_IPV4
    if (a->type == ESP_IPADDR_TYPE_V4) {
        return a->u_addr.ip4.addr == b->u_addr.ip4.addr;
    }
#endif

    return false;
}

mdns_cache_entry_t *mdns_priv_cache_find_entry(const char *hostname, const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol)
{
    mdns_cache_entry_t *entry = s_cache;
    while (entry) {
        if (nullable_names_equal(entry->hostname, hostname) && entry->esp_netif == esp_netif && entry->ip_protocol == ip_protocol) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

mdns_service_cache_t *mdns_priv_cache_find_service(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *instance, const char *service, const char *proto, mdns_cache_entry_t **owner_entry)
{
    mdns_cache_entry_t *entry = s_cache;
    if (owner_entry) {
        *owner_entry = NULL;
    }

    while (entry) {
        if (entry->esp_netif == esp_netif && entry->ip_protocol == ip_protocol) {
            mdns_service_cache_t *service_entry = entry->service_cache_list;
            while (service_entry) {
                if (service_match(service_entry, instance, service, proto)) {
                    if (owner_entry) {
                        *owner_entry = entry;
                    }
                    return service_entry;
                }
                service_entry = service_entry->next;
            }
        }
        entry = entry->next;
    }
    return NULL;
}

static void service_entry_free(mdns_service_cache_t *service_entry)
{
    mdns_mem_free(service_entry->instance_name);
    mdns_mem_free(service_entry->service);
    mdns_mem_free(service_entry->proto);
    while (service_entry->subtype_list) {
        mdns_subtype_t *subtype = service_entry->subtype_list;
        service_entry->subtype_list = subtype->next;
        mdns_mem_free((char *)subtype->subtype);
        mdns_mem_free(subtype);
    }
    while (service_entry->txt_list) {
        mdns_txt_linked_item_t *txt = service_entry->txt_list;
        service_entry->txt_list = service_entry->txt_list->next;
        mdns_mem_free((char *)txt->key);
        mdns_mem_free(txt->value);
        mdns_mem_free(txt);
    }
    mdns_mem_free(service_entry);
}

static void cache_entry_free(mdns_cache_entry_t *entry)
{
    mdns_mem_free(entry->hostname);
    while (entry->addr_list) {
        mdns_ip_addr_t *addr = entry->addr_list;
        entry->addr_list = entry->addr_list->next;
        mdns_mem_free(addr);
    }
    while (entry->service_cache_list) {
        mdns_service_cache_t *service_entry = entry->service_cache_list;
        entry->service_cache_list = entry->service_cache_list->next;
        service_entry_free(service_entry);
    }
    mdns_mem_free(entry);
}

static bool cache_remove_entry_if_empty(mdns_cache_entry_t *entry)
{
    if (!entry || entry->addr_list || entry->service_cache_list) {
        return false;
    }

    mdns_cache_entry_t **entry_ptr = &s_cache;
    while (*entry_ptr) {
        if (*entry_ptr == entry) {
            *entry_ptr = entry->next;
            cache_entry_free(entry);
            return true;
        }
        entry_ptr = &(*entry_ptr)->next;
    }

    return false;
}

static mdns_cache_entry_t *cache_add_entry(const char *hostname, const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol)
{
    mdns_cache_entry_t *entry = mdns_mem_calloc(1, sizeof(mdns_cache_entry_t));
    if (!entry) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }

    if (!mdns_utils_str_null_or_empty(hostname)) {
        entry->hostname = mdns_mem_strdup(hostname);
        if (!entry->hostname) {
            HOOK_MALLOC_FAILED;
            mdns_mem_free(entry);
            return NULL;
        }
    }

    entry->esp_netif = (esp_netif_t *)esp_netif;
    entry->ip_protocol = ip_protocol;
    entry->next = s_cache;
    s_cache = entry;
    return entry;
}

static mdns_cache_entry_t *cache_get_or_add_entry(const char *hostname, const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol)
{
    mdns_cache_entry_t *entry = mdns_priv_cache_find_entry(hostname, esp_netif, ip_protocol);
    return entry ? entry : cache_add_entry(hostname, esp_netif, ip_protocol);
}

static mdns_service_cache_t *cache_add_service(mdns_cache_entry_t *entry, const char *instance, const char *service, const char *proto)
{
    if (!entry) {
        return NULL;
    }

    mdns_service_cache_t *service_entry = mdns_mem_calloc(1, sizeof(mdns_service_cache_t));
    if (!service_entry) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }

    if (!mdns_utils_str_null_or_empty(instance)) {
        service_entry->instance_name = mdns_mem_strdup(instance);
        if (!service_entry->instance_name) {
            HOOK_MALLOC_FAILED;
            service_entry_free(service_entry);
            return NULL;
        }
    }

    if (!mdns_utils_str_null_or_empty(service)) {
        service_entry->service = mdns_mem_strdup(service);
        if (!service_entry->service) {
            HOOK_MALLOC_FAILED;
            service_entry_free(service_entry);
            return NULL;
        }
    }

    if (!mdns_utils_str_null_or_empty(proto)) {
        service_entry->proto = mdns_mem_strdup(proto);
        if (!service_entry->proto) {
            HOOK_MALLOC_FAILED;
            service_entry_free(service_entry);
            return NULL;
        }
    }

    service_entry->next = entry->service_cache_list;
    entry->service_cache_list = service_entry;
    return service_entry;
}

static bool cache_move_service(mdns_cache_entry_t *old_entry, mdns_cache_entry_t *new_entry, mdns_service_cache_t *cache)
{
    if (!old_entry || !new_entry || !cache) {
        return false;
    }

    mdns_service_cache_t **old_entry_cache = &old_entry->service_cache_list;

    while (*old_entry_cache) {
        if (*old_entry_cache == cache) {
            *old_entry_cache = cache->next;
            cache->next = new_entry->service_cache_list;
            new_entry->service_cache_list = cache;

            cache_remove_entry_if_empty(old_entry);
            return true;
        }
        old_entry_cache = &(*old_entry_cache)->next;
    }

    ESP_LOGE(TAG, "No target service in old entry");
    return false;
}

static mdns_cache_update_result_t service_cache_add_subtype(mdns_service_cache_t *service_entry, const char *subtype)
{
    if (!service_entry) {
        return MDNS_CACHE_ERROR;
    }

    if (mdns_utils_str_null_or_empty(subtype)) {
        return MDNS_CACHE_NO_CHANGE;
    }

    mdns_subtype_t **subtype_entry = &service_entry->subtype_list;
    while (*subtype_entry) {
        if (names_equal((*subtype_entry)->subtype, subtype)) {
            return MDNS_CACHE_NO_CHANGE;
        }
        subtype_entry = &(*subtype_entry)->next;
    }

    *subtype_entry = mdns_mem_calloc(1, sizeof(mdns_subtype_t));
    if (!*subtype_entry) {
        HOOK_MALLOC_FAILED;
        return MDNS_CACHE_ERROR;
    }

    (*subtype_entry)->subtype = mdns_mem_strdup(subtype);
    if (!(*subtype_entry)->subtype) {
        HOOK_MALLOC_FAILED;
        mdns_mem_free(*subtype_entry);
        *subtype_entry = NULL;
        return MDNS_CACHE_ERROR;
    }

    return MDNS_CACHE_UPDATED;
}

static bool service_cache_remove_subtype(mdns_service_cache_t *service_entry, const char *subtype)
{
    if (!service_entry || mdns_utils_str_null_or_empty(subtype)) {
        return false;
    }

    mdns_subtype_t **subtype_entry = &service_entry->subtype_list;
    while (*subtype_entry) {
        if (names_equal((*subtype_entry)->subtype, subtype)) {
            mdns_subtype_t *removed_subtype = *subtype_entry;
            *subtype_entry = removed_subtype->next;
            mdns_mem_free((char *)removed_subtype->subtype);
            mdns_mem_free(removed_subtype);
            return true;
        }
        subtype_entry = &(*subtype_entry)->next;
    }
    return false;
}

static bool cache_remove_service(mdns_cache_entry_t *entry, mdns_service_cache_t *service_entry)
{
    if (!entry || !service_entry) {
        return false;
    }

    mdns_service_cache_t **service_entry_ptr = &entry->service_cache_list;
    while (*service_entry_ptr) {
        if (*service_entry_ptr == service_entry) {
            *service_entry_ptr = service_entry->next;
            service_entry_free(service_entry);
            cache_remove_entry_if_empty(entry);
            return true;
        }
        service_entry_ptr = &(*service_entry_ptr)->next;
    }

    return false;
}

mdns_cache_update_result_t mdns_priv_cache_update_ptr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *instance, const char *service, const char *proto, const char *subtype, uint32_t ttl)
{
    mdns_cache_entry_t *owner_entry = NULL;
    mdns_service_cache_t *service_entry = mdns_priv_cache_find_service(esp_netif, ip_protocol, instance, service, proto, &owner_entry);
    bool new_service = false;

    if (ttl == 0) {
        if (!service_entry) {
            return MDNS_CACHE_NO_CHANGE;
        }

        if (!mdns_utils_str_null_or_empty(subtype)) {
            return service_cache_remove_subtype(service_entry, subtype) ? MDNS_CACHE_UPDATED : MDNS_CACHE_NO_CHANGE;
        }

        return cache_remove_service(owner_entry, service_entry) ? MDNS_CACHE_REMOVED : MDNS_CACHE_NO_CHANGE;
    }

    if (!service_entry) {
        // Uncached PTR records will all be stored in hostname == NULL entry temporarily
        owner_entry = cache_get_or_add_entry(NULL, esp_netif, ip_protocol);
        if (!owner_entry) {
            return MDNS_CACHE_ERROR;
        }

        service_entry = cache_add_service(owner_entry, instance, service, proto);
        if (!service_entry) {
            cache_remove_entry_if_empty(owner_entry);
            return MDNS_CACHE_ERROR;
        }
        new_service = true;
    }

    mdns_cache_update_result_t subtype_updated = service_cache_add_subtype(service_entry, subtype);
    if (subtype_updated == MDNS_CACHE_ERROR) {
        return MDNS_CACHE_ERROR;
    }

    bool ttl_changed = update_ttl(&service_entry->ttl, ttl);

    if (new_service) {
        return MDNS_CACHE_ADDED;
    }

    if (subtype_updated == MDNS_CACHE_UPDATED || ttl_changed) {
        return MDNS_CACHE_UPDATED;
    }

    return MDNS_CACHE_NO_CHANGE;
}

static mdns_cache_update_result_t service_cache_srv_update(mdns_service_cache_t *cache, uint16_t priority, uint16_t weight, uint16_t port, uint32_t ttl)
{
    mdns_cache_update_result_t result = MDNS_CACHE_NO_CHANGE;

    if (cache->priority != priority) {
        cache->priority = priority;
        result = MDNS_CACHE_UPDATED;
    }
    if (cache->weight != weight) {
        cache->weight = weight;
        result = MDNS_CACHE_UPDATED;
    }
    if (cache->port != port) {
        cache->port = port;
        result = MDNS_CACHE_UPDATED;
    }
    if (update_ttl(&cache->ttl, ttl)) {
        result = MDNS_CACHE_UPDATED;
    }

    return result;
}

mdns_cache_update_result_t mdns_priv_cache_update_srv(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *hostname, const char *instance, const char *service, const char *proto, uint16_t priority, uint16_t weight, uint16_t port, uint32_t ttl)
{
    mdns_cache_entry_t *owner_entry = NULL;
    mdns_service_cache_t *service_entry = mdns_priv_cache_find_service(esp_netif, ip_protocol, instance, service, proto, &owner_entry);
    mdns_cache_entry_t *host_entry = NULL;
    bool new_entry = false;
    bool moved = false;
    mdns_cache_update_result_t result = MDNS_CACHE_NO_CHANGE;

    if (ttl == 0) {
        return service_entry && cache_remove_service(owner_entry, service_entry) ? MDNS_CACHE_REMOVED : MDNS_CACHE_NO_CHANGE;
    }

    host_entry = cache_get_or_add_entry(hostname, esp_netif, ip_protocol);
    if (!host_entry) {
        return MDNS_CACHE_ERROR;
    }

    if (!service_entry) {
        service_entry = cache_add_service(host_entry, instance, service, proto);
        if (!service_entry) {
            cache_remove_entry_if_empty(host_entry);
            return MDNS_CACHE_ERROR;
        }

        owner_entry = host_entry;
        new_entry = true;
    } else if (owner_entry != host_entry) {
        if (!cache_move_service(owner_entry, host_entry, service_entry)) {
            return MDNS_CACHE_ERROR;
        }
        owner_entry = host_entry;
        moved = true;
    }

    result = service_cache_srv_update(service_entry, priority, weight, port, ttl);

    if (new_entry) {
        return MDNS_CACHE_ADDED;
    }
    if (moved) {
        return MDNS_CACHE_UPDATED;
    }
    return result;
}

static void free_txt_linked_list(mdns_txt_linked_item_t *txt)
{
    while (txt) {
        mdns_txt_linked_item_t *next = txt->next;
        mdns_mem_free((char *)txt->key);
        mdns_mem_free(txt->value);
        mdns_mem_free(txt);
        txt = next;
    }
}

static bool txt_item_equal(const mdns_txt_linked_item_t *a, const mdns_txt_linked_item_t *b)
{
    if (!a || !b || !names_equal(a->key, b->key)) {
        return false;
    }
    if (a->value_len != b->value_len) {
        return false;
    }
    if (a->value_len == 0) {
        return true;
    }
    if (!a->value || !b->value) {
        return false;
    }
    return memcmp(a->value, b->value, a->value_len) == 0;
}

static bool txt_list_contains(const mdns_txt_linked_item_t *txt_list, const mdns_txt_linked_item_t *item)
{
    while (txt_list) {
        if (txt_item_equal(txt_list, item)) {
            return true;
        }
        txt_list = txt_list->next;
    }
    return false;
}

static size_t txt_list_count(const mdns_txt_linked_item_t *txt_list)
{
    size_t count = 0;
    while (txt_list) {
        count++;
        txt_list = txt_list->next;
    }
    return count;
}

static bool txt_list_equal(const mdns_txt_linked_item_t *a, const mdns_txt_linked_item_t *b)
{
    if (a == b) {
        return true;
    }

    if (txt_list_count(a) != txt_list_count(b)) {
        return false;
    }

    for (const mdns_txt_linked_item_t *it = a; it; it = it->next) {
        if (!txt_list_contains(b, it)) {
            return false;
        }
    }

    for (const mdns_txt_linked_item_t *it = b; it; it = it->next) {
        if (!txt_list_contains(a, it)) {
            return false;
        }
    }

    return true;
}

static mdns_cache_update_result_t service_cache_txt_update(mdns_service_cache_t *service_entry, mdns_txt_linked_item_t *new_txt)
{
    if (!service_entry) {
        free_txt_linked_list(new_txt);
        return MDNS_CACHE_ERROR;
    }

    if (txt_list_equal(service_entry->txt_list, new_txt)) {
        free_txt_linked_list(new_txt);
        return MDNS_CACHE_NO_CHANGE;
    }

    mdns_txt_linked_item_t *old_txt = service_entry->txt_list;
    service_entry->txt_list = new_txt;
    free_txt_linked_list(old_txt);
    return MDNS_CACHE_UPDATED;
}

mdns_cache_update_result_t mdns_priv_cache_update_txt(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *instance, const char *service, const char *proto, mdns_txt_linked_item_t *txt, uint32_t ttl)
{
    mdns_cache_entry_t *owner_entry = NULL;
    mdns_service_cache_t *service_entry = mdns_priv_cache_find_service(esp_netif, ip_protocol, instance, service, proto, &owner_entry);
    mdns_cache_update_result_t result = MDNS_CACHE_NO_CHANGE;
    bool new_service = false;

    if (ttl == 0) {
        free_txt_linked_list(txt);
        return service_entry && cache_remove_service(owner_entry, service_entry) ? MDNS_CACHE_REMOVED : MDNS_CACHE_NO_CHANGE;
    }

    if (!service_entry) {
        owner_entry = cache_get_or_add_entry(NULL, esp_netif, ip_protocol);
        if (!owner_entry) {
            free_txt_linked_list(txt);
            return MDNS_CACHE_ERROR;
        }

        service_entry = cache_add_service(owner_entry, instance, service, proto);
        if (!service_entry) {
            cache_remove_entry_if_empty(owner_entry);
            free_txt_linked_list(txt);
            return MDNS_CACHE_ERROR;
        }

        new_service = true;
    }

    result = service_cache_txt_update(service_entry, txt);
    bool ttl_changed = update_ttl(&service_entry->ttl, ttl);

    if (new_service) {
        return MDNS_CACHE_ADDED;
    }
    if (ttl_changed) {
        return MDNS_CACHE_UPDATED;
    }
    return result;
}

mdns_cache_update_result_t mdns_priv_cache_update_addr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *hostname, const esp_ip_addr_t *addr, uint32_t ttl)
{
    mdns_cache_entry_t *entry = NULL;
    if (ttl == 0) {
        entry = mdns_priv_cache_find_entry(hostname, esp_netif, ip_protocol);
        if (!entry) {
            return MDNS_CACHE_NO_CHANGE;
        }

        // Remove addr
        mdns_ip_addr_t **addr_ptr = &entry->addr_list;
        while (*addr_ptr) {
            if (addr_equal(&(*addr_ptr)->addr, addr)) {
                mdns_ip_addr_t *removed_addr = *addr_ptr;
                *addr_ptr = removed_addr->next;
                mdns_mem_free(removed_addr);
                cache_remove_entry_if_empty(entry);
                return MDNS_CACHE_REMOVED;
            }
            addr_ptr = &(*addr_ptr)->next;
        }

        return MDNS_CACHE_NO_CHANGE;
    }

    bool addr_added = false;
    bool ttl_changed = false;

    entry = cache_get_or_add_entry(hostname, esp_netif, ip_protocol);
    if (!entry) {
        return MDNS_CACHE_ERROR;
    }

    mdns_ip_addr_t *addr_entry = entry->addr_list;
    while (addr_entry) {
        if (addr_equal(&addr_entry->addr, addr)) {
            break;
        }
        addr_entry = addr_entry->next;
    }

    if (!addr_entry) {
        mdns_ip_addr_t *new_addr = mdns_mem_calloc(1, sizeof(mdns_ip_addr_t));
        if (!new_addr) {
            HOOK_MALLOC_FAILED;
            cache_remove_entry_if_empty(entry);
            return MDNS_CACHE_ERROR;
        }
        new_addr->addr = *addr;
        new_addr->next = entry->addr_list;
        entry->addr_list = new_addr;
        addr_added = true;
    }

    for (mdns_service_cache_t *service = entry->service_cache_list; service; service = service->next) {
        ttl_changed = update_ttl(&service->ttl, ttl) || ttl_changed;
    }

    return addr_added || ttl_changed ? MDNS_CACHE_UPDATED : MDNS_CACHE_NO_CHANGE;
}

void mdns_priv_cache_clear(void)
{
    while (s_cache) {
        mdns_cache_entry_t *entry = s_cache;
        s_cache = s_cache->next;
        cache_entry_free(entry);
    }
}
