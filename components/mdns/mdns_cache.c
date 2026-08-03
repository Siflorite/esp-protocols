/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <strings.h>
#include "esp_log.h"
#include "mdns_cache.h"
#include "mdns_mem_caps.h"
#include "mdns_querier.h"
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

static void cache_print(void)
{
#ifdef CONFIG_MDNS_CACHE_DEBUG
    ESP_LOGI(TAG, "========== mDNS cache ==========");

    for (mdns_cache_entry_t *entry = s_cache; entry; entry = entry->next) {
        const char *ip_protocol_str = NULL;
        switch (entry->ip_protocol) {
        case MDNS_IP_PROTOCOL_V4:
            ip_protocol_str = "IPv4";
            break;
        case MDNS_IP_PROTOCOL_V6:
            ip_protocol_str = "IPv6";
            break;
        case MDNS_IP_PROTOCOL_MAX:
            ip_protocol_str = "Max";
            break;
        default:
            ip_protocol_str = "Unknown";
            break;
        }
        ESP_LOGI(TAG, "entry host=%s netif=%p protocol=%s",
                 entry->hostname ? entry->hostname : "<unresolved>",
                 entry->esp_netif,
                 ip_protocol_str);

        ESP_LOGI(TAG, "addresses:");
        for (mdns_ip_addr_t *addr = entry->addr_list; addr; addr = addr->next) {
#ifdef CONFIG_LWIP_IPV4
            if (addr->addr.type == ESP_IPADDR_TYPE_V4) {
                ESP_LOGI(TAG, "  A: " IPSTR, IP2STR(&addr->addr.u_addr.ip4));
            }
#endif
#ifdef CONFIG_LWIP_IPV6
            if (addr->addr.type == ESP_IPADDR_TYPE_V6) {
                ESP_LOGI(TAG, "  AAAA: " IPV6STR, IPV62STR(addr->addr.u_addr.ip6));
            }
#endif
        }

        ESP_LOGI(TAG, "services:");
        for (mdns_service_cache_t *service = entry->service_cache_list; service; service = service->next) {
            ESP_LOGI(TAG, "  service=%s.%s.%s port=%u ttl=%" PRIu32,
                     service->instance_name,
                     service->service,
                     service->proto,
                     service->port,
                     service->ttl);
            ESP_LOGI(TAG, "  subtypes:");
            for (mdns_subtype_t *subtype = service->subtype_list; subtype; subtype = subtype->next) {
                ESP_LOGI(TAG, "    %s", subtype->subtype);
            }
            ESP_LOGI(TAG, "  txts:");
            for (mdns_txt_linked_item_t *txt = service->txt_list; txt; txt = txt->next) {
                ESP_LOGI(TAG, "    %s=%s length=%u", txt->key, txt->value, txt->value_len);
            }
        }
    }
    ESP_LOGI(TAG, "===============================");
#endif
}

static void cache_finish_update(const char *record_type, mdns_cache_update_result_t result)
{
#ifdef CONFIG_MDNS_CACHE_DEBUG
    if (result == MDNS_CACHE_ERROR || result == MDNS_CACHE_NO_CHANGE) {
        return;
    }
    ESP_LOGI(TAG, "cache_finish_update: %s result=%d", record_type, result);
    cache_print();
#endif
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
    mdns_cache_update_result_t result = MDNS_CACHE_NO_CHANGE;
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

    result = service_cache_add_subtype(service_entry, subtype);
    if (result == MDNS_CACHE_ERROR) {
        return MDNS_CACHE_ERROR;
    }

    bool ttl_changed = update_ttl(&service_entry->ttl, ttl);

    if (new_service) {
        result = MDNS_CACHE_ADDED;
    } else if (ttl_changed) {
        result = MDNS_CACHE_UPDATED;
    }

    cache_finish_update("PTR", result);
    return result;
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
        result = MDNS_CACHE_ADDED;
    } else if (moved) {
        result = MDNS_CACHE_UPDATED;
    }
    cache_finish_update("SRV", result);
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
        result = MDNS_CACHE_ADDED;
    } else if (ttl_changed) {
        result = MDNS_CACHE_UPDATED;
    }
    cache_finish_update("TXT", result);
    return result;
}

mdns_cache_update_result_t mdns_priv_cache_update_addr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *hostname, const esp_ip_addr_t *addr, uint32_t ttl)
{
    mdns_cache_entry_t *entry = NULL;
    bool addr_added = false;
    bool ttl_changed = false;
    mdns_cache_update_result_t result = MDNS_CACHE_NO_CHANGE;

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

    result = (addr_added || ttl_changed) ? MDNS_CACHE_UPDATED : MDNS_CACHE_NO_CHANGE;
    cache_finish_update("ADDR", result);
    return result;
}

void mdns_priv_cache_clear(void)
{
    while (s_cache) {
        mdns_cache_entry_t *entry = s_cache;
        s_cache = s_cache->next;
        cache_entry_free(entry);
    }
}

static bool service_cache_has_subtype(const mdns_service_cache_t *service_entry, const char *subtype)
{
    if (mdns_utils_str_null_or_empty(subtype)) {
        return true;
    }

    for (const mdns_subtype_t *subtype_list = service_entry->subtype_list; subtype_list; subtype_list = subtype_list->next) {
        if (names_equal(subtype_list->subtype, subtype)) {
            return true;
        }
    }
    return false;
}

static bool service_cache_matches_browse(const mdns_service_cache_t *service, const mdns_browse_t *browse)
{
    if (!names_equal(service->service, browse->service) || !names_equal(service->proto, browse->proto)) {
        return false;
    }

    return service_cache_has_subtype(service, browse->subtype);
}

static mdns_txt_item_t *project_txt(const mdns_txt_linked_item_t *txt_list, uint8_t **out_value_len, size_t *out_count)
{
    *out_value_len = NULL;
    *out_count = 0;

    size_t count = 0;
    for (const mdns_txt_linked_item_t *txt = txt_list; txt; txt = txt->next) {
        count++;
    }
    if (count == 0) {
        return NULL;
    }

    mdns_txt_item_t *txt_items = mdns_mem_calloc(count, sizeof(mdns_txt_item_t));
    if (!txt_items) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }
    uint8_t *value_len = mdns_mem_calloc(count, sizeof(uint8_t));
    if (!value_len) {
        HOOK_MALLOC_FAILED;
        mdns_mem_free(txt_items);
        return NULL;
    }

    size_t i = 0;
    for (const mdns_txt_linked_item_t *txt = txt_list; txt; txt = txt->next, i++) {
        txt_items[i].key = mdns_mem_strdup(txt->key);

        value_len[i] = txt->value_len;
        if (txt->value_len > 0 && txt->value) {
            char *value = mdns_mem_calloc(txt->value_len + 1, sizeof(char));
            if (!value || ! txt_items[i].key) {
                HOOK_MALLOC_FAILED;
                for (size_t j = 0; j <= i; j++) {
                    mdns_mem_free((char *)txt_items[j].key);
                    mdns_mem_free((char *)txt_items[j].value);
                }
                mdns_mem_free(value_len);
                mdns_mem_free(txt_items);
                return NULL;
            }

            memcpy(value, txt->value, txt->value_len);
            txt_items[i].value = value;
        } else {
            txt_items[i].value = NULL;
        }
    }

    *out_value_len = value_len;
    *out_count = count;
    return txt_items;
}

static mdns_ip_addr_t *project_addr(const mdns_ip_addr_t *addr_list)
{
    mdns_ip_addr_t *head = NULL;
    mdns_ip_addr_t **tail = &head;

    for (const mdns_ip_addr_t *addr = addr_list; addr; addr = addr->next) {
        mdns_ip_addr_t *new_addr = mdns_mem_calloc(1, sizeof(mdns_ip_addr_t));
        if (!new_addr) {
            HOOK_MALLOC_FAILED;
            while (head) {
                mdns_ip_addr_t *next = head->next;
                mdns_mem_free(head);
                head = next;
            }
            return NULL;
        }
        new_addr->addr = addr->addr;
        *tail = new_addr;
        tail = &new_addr->next;
    }

    return head;
}

static mdns_result_t *service_cache_to_result(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    mdns_result_t *result = mdns_mem_calloc(1, sizeof(mdns_result_t));
    if (!result) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }

    result->esp_netif = entry->esp_netif;
    result->ttl = service->ttl;
    result->ip_protocol = entry->ip_protocol;
    result->instance_name = mdns_mem_strdup(service->instance_name);
    result->service_type = mdns_mem_strdup(service->service);
    result->proto = mdns_mem_strdup(service->proto);
    if (entry->hostname) {
        result->hostname = mdns_mem_strdup(entry->hostname);
    }
    result->port = service->port;
    result->txt = project_txt(service->txt_list, &result->txt_value_len, &result->txt_count);
    result->addr = project_addr(entry->addr_list);

    if (!result->instance_name || !result->service_type || !result->proto || (entry->hostname && !result->hostname) || !result->txt || !result->addr) {
        HOOK_MALLOC_FAILED;
        mdns_priv_query_results_free(result);
    }

    return result;
}

mdns_result_t *mdns_priv_cache_to_result(const mdns_browse_t *browse)
{
    mdns_result_t *results = NULL;
    if (!browse) {
        return NULL;
    }

    for (mdns_cache_entry_t *entry = s_cache; entry; entry = entry->next) {
        for (mdns_service_cache_t *service = entry->service_cache_list; service; service = service->next) {
            if (!service_cache_matches_browse(service, browse)) {
                continue;
            }

            mdns_result_t *r = service_cache_to_result(entry, service);
            if (!r) {
                mdns_priv_query_results_free(r);
                continue;
            }

            r->next = results;
            results = r;
        }
    }
    return results;
}

static bool addr_in_list(const esp_ip_addr_t *addr, const mdns_ip_addr_t *addr_list)
{
    for (const mdns_ip_addr_t *a = addr_list; a; a = a->next) {
        if (addr_equal(&a->addr, addr)) {
            return true;
        }
    }
    return false;
}

static bool txt_in_list(const mdns_txt_item_t *txt, uint8_t value_len, const mdns_txt_item_t *txt_list, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (names_equal(txt->key, txt_list[i].key)) {
            if (!txt->value && !txt_list[i].value) {
                return true;
            }
            if (!txt->value || !txt_list[i].value) {
                return false;
            }
            if (memcmp(txt->value, txt_list[i].value, value_len) == 0) {
                return true;
            }
        }
    }
    return false;
}

static bool result_equals(const mdns_result_t *a, const mdns_result_t *b)
{
    if (a->esp_netif != b->esp_netif) {
        return false;
    }
    if (a->ttl != b->ttl) {
        return false;
    }
    if (a->ip_protocol != b->ip_protocol) {
        return false;
    }
    if (!nullable_names_equal(a->instance_name, b->instance_name)) {
        return false;
    }
    if (!nullable_names_equal(a->service_type, b->service_type)) {
        return false;
    }
    if (!nullable_names_equal(a->proto, b->proto)) {
        return false;
    }
    if (!nullable_names_equal(a->hostname, b->hostname)) {
        return false;
    }
    if (a->port != b->port) {
        return false;
    }
    if (a->txt_count != b->txt_count) {
        return false;
    }
    for (size_t i = 0; i < a->txt_count; i++) {
        if (!txt_in_list(&a->txt[i], a->txt_value_len[i], b->txt, b->txt_count)) {
            return false;
        }
    }
    for (const mdns_ip_addr_t *addr = a->addr; addr; addr = addr->next) {
        if (!addr_in_list(&addr->addr, b->addr)) {
            return false;
        }
    }
    return true;
}

void mdns_priv_cache_verify_browse_result(const mdns_browse_t *browse)
{
#ifdef CONFIG_MDNS_CACHE_DEBUG
    mdns_result_t *results_from_cache = mdns_priv_cache_to_result(browse);
    if (!results_from_cache) {
        ESP_LOGW(TAG, "No results found in cache for browse %s", browse->service);
        return;
    }
    const mdns_result_t *results_from_browse = browse->result;

    ESP_LOGI(TAG, "==== cache vs browse verify (%s.%s subtype=%s) ====",
             browse->service, browse->proto,
             browse->subtype ? browse->subtype : "<none>");

    const mdns_result_t *it_c = results_from_cache;
    const mdns_result_t *it_b = results_from_browse;
    int count_c = 0;
    int count_b = 0;
    while (it_c) {
        count_c++;
        it_c = it_c->next;
    }
    while (it_b) {
        count_b++;
        it_b = it_b->next;
    }

    if (count_c != count_b) {
        ESP_LOGW(TAG, "Cache and browse results have different lengths: %d vs %d", count_c, count_b);
        return;
    }

    for (const mdns_result_t *cr = results_from_cache; cr; cr = cr->next) {
        bool found = false;
        for (const mdns_result_t *br = results_from_browse; br; br = br->next) {
            if (result_equals(cr, br)) {
                found = true;
                break;
            }
        }
        if (!found) {
            ESP_LOGW(TAG, "Result not found in browse: %s", cr->instance_name);
        }
    }

    mdns_priv_query_results_free(results_from_cache);
#endif
}
