/*
 * SPDX-FileCopyrightText: 2015-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include "sdkconfig.h"
#include "mdns_private.h"
#include "mdns_browser.h"
#include "mdns_mem_caps.h"
#include "mdns_debug.h"
#include "mdns_utils.h"
#include "mdns_querier.h"
#include "mdns_responder.h"
#include "mdns_netif.h"
#include "mdns_service.h"
#include "esp_log.h"
#include "mdns_cache.h"

static const char *TAG = "mdns_browser";

static mdns_browse_t *s_browse;

/**
 * @brief  Browse action
 */
static esp_err_t send_browse_action(mdns_action_type_t type, mdns_browse_t *browse)
{
    mdns_action_t *action = NULL;

    action = (mdns_action_t *)mdns_mem_malloc(sizeof(mdns_action_t));

    if (!action) {
        HOOK_MALLOC_FAILED;
        return ESP_ERR_NO_MEM;
    }

    action->type = type;
    action->data.browse_add.browse = browse;
    if (!mdns_priv_queue_action(action)) {
        mdns_mem_free(action);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/**
 * @brief  Free a browse item (Not free the list).
 */
static void browse_item_free(mdns_browse_t *browse)
{
    mdns_mem_free(browse->service);
    mdns_mem_free(browse->proto);
    mdns_mem_free(browse->subtype);
    if (browse->result) {
        mdns_priv_query_results_free(browse->result);
    }
    mdns_mem_free(browse);
}

/**
 * @brief Deliver browse updates to the user notifier
 *
 * Invokes the notifier once per changed result accumulated for the current
 * packet. The passed @c result pointer is a live node in @c browse->result;
 * @c result->next is not cleared before the callback (only after TTL=0 removal).
 * See @ref mdns_browse_notify_t for how callers should use @c next.
 */
static void browse_sync(mdns_browse_sync_t *browse_sync)
{
    mdns_browse_t *browse = browse_sync->browse;
    mdns_browse_result_sync_t *sync_result = browse_sync->sync_result;
    while (sync_result) {
        mdns_result_t *result = sync_result->result;
        DBG_BROWSE_RESULTS(result, browse_sync->browse);
        browse->notifier(result);
        if (result->ttl == 0) {
            queueDetach(mdns_result_t, browse->result, result);
            // Just free current result
            result->next = NULL;
            mdns_priv_query_results_free(result);
        }
        sync_result = sync_result->next;
    }
}

/**
 * @brief  Send PTR query packet to all available interfaces for browsing.
 */
static void browse_send(mdns_browse_t *browse, mdns_if_t interface, mdns_ip_protocol_t ip_protocol)
{
    // Using search once for sending the PTR query
    mdns_search_once_t search = {0};

    search.instance = NULL;
    search.service = browse->service;
    search.proto = browse->proto;
    search.subtype = browse->subtype;
    search.type = MDNS_TYPE_PTR;
    search.unicast = false;
    search.result = NULL;
    search.next = NULL;
    mdns_priv_query_send(&search, interface, ip_protocol);
}

void mdns_priv_browse_send_by_ip_protocol(mdns_if_t mdns_if, mdns_ip_protocol_t ip_protocol)
{
    mdns_browse_t *browse = s_browse;
    while (browse) {
        browse_send(browse, mdns_if, ip_protocol);
        browse = browse->next;
    }
}

void mdns_priv_browse_send_all(mdns_if_t mdns_if)
{
    for (uint8_t protocol_idx = 0; protocol_idx < MDNS_IP_PROTOCOL_MAX; protocol_idx++) {
        mdns_priv_browse_send_by_ip_protocol(mdns_if, (mdns_ip_protocol_t) protocol_idx);
    }
}

void mdns_priv_browse_free(void)
{
    while (s_browse) {
        mdns_browse_t *b = s_browse;
        s_browse = s_browse->next;
        browse_item_free(b);
    }
}

static bool browse_match(const mdns_browse_t *a, const mdns_browse_t *b)
{
    if (strlen(a->service) != strlen(b->service) || memcmp(a->service, b->service, strlen(a->service)) != 0) {
        return false;
    }
    if (strlen(a->proto) != strlen(b->proto) || memcmp(a->proto, b->proto, strlen(a->proto)) != 0) {
        return false;
    }
    if (!a->subtype && !b->subtype) {
        return true;
    }
    if (!a->subtype || !b->subtype) {
        return false;
    }
    return (strlen(a->subtype) == strlen(b->subtype) && memcmp(a->subtype, b->subtype, strlen(a->subtype)) == 0);
}

static bool browse_has_service(const char *service, const char *proto)
{
    for (const mdns_browse_t *it = s_browse; it; it = it->next) {
        if (it->state == BROWSE_RUNNING && !mdns_utils_str_null_or_empty(it->service)
                && !mdns_utils_str_null_or_empty(it->proto) && !strcasecmp(service, it->service) && !strcasecmp(proto, it->proto)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief  Mark browse as finished, remove and free it from browse chain
 */
static void browse_finish(mdns_browse_t *browse)
{
    bool removed = false;
    browse->state = BROWSE_OFF;
    ESP_LOGI(TAG, "Browse finished: %s, %s, %s", browse->service, browse->proto, browse->subtype);
    for (mdns_browse_t *it = s_browse; it; it = it->next) {
        if (browse_match(it, browse)) {
            queueDetach(mdns_browse_t, s_browse, it);
            browse_item_free(it);
            removed = true;
            break;
        }
    }

    if (removed) {
        ESP_LOGI(TAG, "Browse removed: %s, %s, %s", browse->service, browse->proto, browse->subtype);
        if (!browse_has_service(browse->service, browse->proto)) {
            ESP_LOGI(TAG, "Service caches to be removed: %s, %s", browse->service, browse->proto);
            mdns_priv_remove_service_caches(browse->service, browse->proto);
        } else if (!mdns_utils_str_null_or_empty(browse->subtype)) {
            ESP_LOGI(TAG, "Subtype to be removed: %s, %s, %s", browse->service, browse->proto, browse->subtype);
            mdns_priv_service_cache_remove_subtype(browse->service, browse->proto, browse->subtype);
        }
    }

    browse_item_free(browse);
}

/**
 * @brief  Allocate new browse structure
 */
static mdns_browse_t *browse_init(const char *service, const char *proto, const char *subtype, mdns_browse_notify_t notifier)
{
    mdns_browse_t *browse = (mdns_browse_t *)mdns_mem_malloc(sizeof(mdns_browse_t));

    if (!browse) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }
    memset(browse, 0, sizeof(mdns_browse_t));

    browse->state = BROWSE_INIT;
    if (!mdns_utils_str_null_or_empty(service)) {
        browse->service = mdns_mem_strndup(service, MDNS_NAME_BUF_LEN - 1);
        if (!browse->service) {
            browse_item_free(browse);
            HOOK_MALLOC_FAILED;
            return NULL;
        }
    }

    if (!mdns_utils_str_null_or_empty(proto)) {
        browse->proto = mdns_mem_strndup(proto, MDNS_NAME_BUF_LEN - 1);
        if (!browse->proto) {
            browse_item_free(browse);
            return NULL;
        }
    }

    if (!mdns_utils_str_null_or_empty(subtype)) {
        browse->subtype = mdns_mem_strndup(subtype, MDNS_NAME_BUF_LEN - 1);
        if (!browse->subtype) {
            browse_item_free(browse);
            return NULL;
        }
    }

    browse->notifier = notifier;
    return browse;
}

/**
 * @brief  Add new browse to the browse chain
 */
static void browse_add(mdns_browse_t *browse)
{
    browse->state = BROWSE_RUNNING;
    mdns_browse_t *queue = s_browse;
    bool found = false;
    // looking for this browse in active browses
    while (queue) {
        if (browse_match(queue, browse)) {
            found = true;
            break;
        }
        queue = queue->next;
    }
    if (!found) {
        browse->next = s_browse;
        s_browse = browse;
    }
    for (uint8_t interface_idx = 0; interface_idx < MDNS_MAX_INTERFACES; interface_idx++) {
        for (uint8_t protocol_idx = 0; protocol_idx < MDNS_IP_PROTOCOL_MAX; protocol_idx++) {
            browse_send(browse, (mdns_if_t) interface_idx, (mdns_ip_protocol_t) protocol_idx);
        }
    }
    if (found) {
        ESP_LOGI(TAG, "Browse already exists: %s, %s, %s", browse->service, browse->proto, browse->subtype);
        browse_item_free(browse);
    }
    ESP_LOGI(TAG, "Browse added: %s, %s, %s", browse->service, browse->proto, browse->subtype);
}

static esp_err_t add_browse_result(mdns_browse_sync_t *sync_browse, mdns_result_t *r);

/**
 * @brief  Called from packet parser to find matching running search
 *
 * @note Called from the mDNS service task while the service lock is held.
 *       The returned browse is an active cache node that the parser may update.
 */
mdns_browse_t *mdns_priv_browse_find_ptr(mdns_name_t *name)
{
    mdns_browse_t *b = s_browse;

    if (mdns_utils_str_null_or_empty(name->service) || mdns_utils_str_null_or_empty(name->proto)) {
        return NULL;
    }

    while (b) {
        bool browse_has_subtype = !mdns_utils_str_null_or_empty(b->subtype);
        bool subtype_matches = name->sub ? browse_has_subtype && !mdns_utils_str_null_or_empty(name->host)
                               && !strcasecmp(name->host, b->subtype) : !browse_has_subtype;

        if (!strcasecmp(name->service, b->service) && !strcasecmp(name->proto, b->proto) && subtype_matches) {
            return b;
        }
        b = b->next;
    }
    return NULL;
}

/**
 * @note Only one browse sync object is kept per parsed packet.  If @p sync
 *       is already allocated for a *different* browse, this function returns
 *       the existing object unchanged — callers that compare
 *       out_sync_browse->browse against the current browse will silently
 *       skip the update.  This is acceptable because mDNS answers for
 *       multiple browsed service types in a single packet are uncommon.
 *       The returned object must still be checked by the caller because NULL
 *       means allocation failed when @p browse was non-NULL.
 */
mdns_browse_sync_t *mdns_priv_browse_ensure_sync(mdns_browse_t *browse, mdns_browse_sync_t *sync)
{
    if (!browse) {
        return sync;
    }
    if (!sync) {
        sync = (mdns_browse_sync_t *)mdns_mem_malloc(sizeof(mdns_browse_sync_t));
        if (!sync) {
            HOOK_MALLOC_FAILED;
            return NULL;
        }
        sync->browse = browse;
        sync->sync_result = NULL;
    }
    return sync;
}

void mdns_priv_browse_staged_ip_free(mdns_browse_staged_ip_t *staged)
{
    while (staged) {
        mdns_browse_staged_ip_t *next = staged->next;
        mdns_mem_free(staged);
        staged = next;
    }
}

esp_err_t mdns_priv_browse_stage_ip(mdns_browse_staged_ip_t **staged, const char *hostname, esp_ip_addr_t *ip,
                                    mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol, uint32_t ttl)
{
    mdns_browse_staged_ip_t *item = (mdns_browse_staged_ip_t *)mdns_mem_malloc(sizeof(mdns_browse_staged_ip_t));
    if (!item) {
        HOOK_MALLOC_FAILED;
        return ESP_ERR_NO_MEM;
    }
    memset(item, 0, sizeof(mdns_browse_staged_ip_t));
    strncpy(item->hostname, hostname, MDNS_NAME_BUF_LEN - 1);
    item->hostname[MDNS_NAME_BUF_LEN - 1] = '\0';
    item->ip = *ip;
    item->tcpip_if = tcpip_if;
    item->ip_protocol = ip_protocol;
    item->ttl = ttl;
    item->next = *staged;
    *staged = item;
    return ESP_OK;
}

/**
 * @brief Apply packet-staged A/AAAA records after SRV hostnames are known
 *
 * @note Each staged address is applied via mdns_priv_browse_result_add_ip(), which
 *       attaches the address only to the first browse result with a matching
 *       hostname on the same interface and IP protocol. Additional instances that
 *       share the same target host do not receive a copy automatically.
 */
void mdns_priv_browse_apply_staged_ips(mdns_browse_t *browse, mdns_browse_staged_ip_t *staged,
                                       mdns_browse_sync_t *out_sync_browse)
{
    if (!browse || !staged || !out_sync_browse || out_sync_browse->browse != browse) {
        return;
    }
    while (staged) {
        mdns_priv_browse_result_add_ip(browse, staged->hostname, &staged->ip, staged->tcpip_if,
                                       staged->ip_protocol, staged->ttl, out_sync_browse);
        staged = staged->next;
    }
}

void mdns_priv_browse_result_add_ptr(mdns_browse_t *browse, const char *instance, const char *service, const char *proto,
                                     mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol, uint32_t ttl,
                                     mdns_browse_sync_t *out_sync_browse)
{
    if (!browse || !out_sync_browse || out_sync_browse->browse != browse
            || mdns_utils_str_null_or_empty(instance) || mdns_utils_str_null_or_empty(service)
            || mdns_utils_str_null_or_empty(proto)) {
        return;
    }
    mdns_result_t *r = browse->result;
    while (r) {
        if (r->esp_netif == mdns_priv_get_esp_netif(tcpip_if) && r->ip_protocol == ip_protocol &&
                !mdns_utils_str_null_or_empty(r->instance_name) && !strcasecmp(instance, r->instance_name) &&
                !mdns_utils_str_null_or_empty(r->service_type) && !strcasecmp(service, r->service_type) &&
                !mdns_utils_str_null_or_empty(r->proto) && !strcasecmp(proto, r->proto)) {
            if (r->ttl != ttl) {
                uint32_t previous_ttl = r->ttl;
                if (r->ttl == 0) {
                    r->ttl = ttl;
                } else {
                    mdns_priv_query_update_result_ttl(r, ttl);
                }
                if (previous_ttl != r->ttl) {
                    add_browse_result(out_sync_browse, r);
                }
            }
            return;
        }
        r = r->next;
    }

    r = (mdns_result_t *)mdns_mem_malloc(sizeof(mdns_result_t));
    if (!r) {
        HOOK_MALLOC_FAILED;
        return;
    }
    memset(r, 0, sizeof(mdns_result_t));
    r->instance_name = mdns_mem_strdup(instance);
    r->service_type = mdns_mem_strdup(service);
    r->proto = mdns_mem_strdup(proto);
    if (!r->instance_name || !r->service_type || !r->proto) {
        HOOK_MALLOC_FAILED;
        mdns_mem_free(r->instance_name);
        mdns_mem_free(r->service_type);
        mdns_mem_free(r->proto);
        mdns_mem_free(r);
        return;
    }
    r->esp_netif = mdns_priv_get_esp_netif(tcpip_if);
    r->ip_protocol = ip_protocol;
    r->ttl = ttl;
    r->next = browse->result;
    browse->result = r;
    add_browse_result(out_sync_browse, r);
}

mdns_browse_t *mdns_priv_browse_find(mdns_name_t *name, uint16_t type, mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol)
{
    mdns_browse_t *b = s_browse;
    // For browse, we only care about the SRV, TXT, A and AAAA
    if (type != MDNS_TYPE_SRV && type != MDNS_TYPE_A && type != MDNS_TYPE_AAAA && type != MDNS_TYPE_TXT) {
        return NULL;
    }

    while (b) {
        if (type == MDNS_TYPE_SRV || type == MDNS_TYPE_TXT) {
            if (strcasecmp(name->service, b->service)
                    || strcasecmp(name->proto, b->proto)) {
                b = b->next;
                continue;
            }
            return b;
        } else if (type == MDNS_TYPE_A || type == MDNS_TYPE_AAAA) {
            if (mdns_priv_host_has_service(name->host, mdns_priv_get_esp_netif(tcpip_if), ip_protocol, b->service, b->proto)) {
                return b;
            }
            b = b->next;
            continue;
        }
    }
    return NULL;
}

static void sync_browse_result_link_free(mdns_browse_sync_t *browse_sync)
{
    mdns_browse_result_sync_t *current = browse_sync->sync_result;
    mdns_browse_result_sync_t *need_free;
    while (current) {
        need_free = current;
        current = current->next;
        mdns_mem_free(need_free);
    }
    mdns_mem_free(browse_sync);
}

void mdns_priv_browse_sync_free(mdns_browse_sync_t *browse_sync)
{
    if (!browse_sync) {
        return;
    }
    sync_browse_result_link_free(browse_sync);
}

void mdns_priv_browse_action(mdns_action_t *action, mdns_action_subtype_t type)
{
    if (type == ACTION_RUN) {
        switch (action->type) {
        case ACTION_BROWSE_ADD:
            browse_add(action->data.browse_add.browse);
            break;
        case ACTION_BROWSE_SYNC:
            browse_sync(action->data.browse_sync.browse_sync);
            sync_browse_result_link_free(action->data.browse_sync.browse_sync);
            break;
        case ACTION_BROWSE_END:
            browse_finish(action->data.browse_add.browse);
            break;
        default:
            abort();
        }
        return;
    }
    if (type == ACTION_CLEANUP) {
        switch (action->type) {
        case ACTION_BROWSE_ADD:
        //fallthrough
        case ACTION_BROWSE_END:
            browse_item_free(action->data.browse_add.browse);
            break;
        case ACTION_BROWSE_SYNC:
            sync_browse_result_link_free(action->data.browse_sync.browse_sync);
            break;
        default:
            abort();
        }
        return;
    }

}

/**
 * @brief  Add result to browse, only add when the result is a new one.
 */
static esp_err_t add_browse_result(mdns_browse_sync_t *sync_browse, mdns_result_t *r)
{
    mdns_browse_result_sync_t *sync_r = sync_browse->sync_result;
    while (sync_r) {
        if (sync_r->result == r) {
            break;
        }
        sync_r = sync_r->next;
    }
    if (!sync_r) {
        // Do not find, need to add the result to the list
        mdns_browse_result_sync_t *new = (mdns_browse_result_sync_t *)mdns_mem_malloc(sizeof(mdns_browse_result_sync_t));

        if (!new) {
            HOOK_MALLOC_FAILED;
            return ESP_ERR_NO_MEM;
        }
        new->result = r;
        new->next = sync_browse->sync_result;
        sync_browse->sync_result = new;
    }
    return ESP_OK;
}

/**
 * @brief  Called from parser to add A/AAAA data to browse result
 *
 * @note Only the first browse result with a matching @p hostname (same interface
 *       and IP protocol) receives the address. This predates browse staging and
 *       also limits mdns_priv_browse_apply_staged_ips() when several instances
 *       share one target host.
 */
void mdns_priv_browse_result_add_ip(mdns_browse_t *browse, const char *hostname, esp_ip_addr_t *ip,
                                    mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol, uint32_t ttl, mdns_browse_sync_t *out_sync_browse)
{
    if (out_sync_browse->browse == NULL) {
        return;
    } else {
        if (out_sync_browse->browse != browse) {
            return;
        }
    }
    mdns_result_t *r = NULL;
    mdns_ip_addr_t *r_a = NULL;
    if (browse) {
        r = browse->result;
        while (r) {
            if (r->ip_protocol == ip_protocol) {
                // Find the target result in browse result.
                if (r->esp_netif == mdns_priv_get_esp_netif(tcpip_if) && !mdns_utils_str_null_or_empty(r->hostname) && !strcasecmp(hostname, r->hostname)) {
                    r_a = r->addr;
                    // Check if the address has already added in result.
                    while (r_a) {
#ifdef CONFIG_LWIP_IPV4
                        if (r_a->addr.type == ip->type && r_a->addr.type == ESP_IPADDR_TYPE_V4 && r_a->addr.u_addr.ip4.addr == ip->u_addr.ip4.addr) {
                            break;
                        }
#endif
#ifdef CONFIG_LWIP_IPV6
                        if (r_a->addr.type == ip->type && r_a->addr.type == ESP_IPADDR_TYPE_V6 && !memcmp(r_a->addr.u_addr.ip6.addr, ip->u_addr.ip6.addr, 16)) {
                            break;
                        }
#endif
                        r_a = r_a->next;
                    }
                    if (!r_a) {
                        // The current IP is a new one, add it to the link list.
                        mdns_ip_addr_t *a = NULL;
                        a = mdns_priv_result_addr_create_ip(ip);
                        if (!a) {
                            return;
                        }
                        a->next = r->addr;
                        r->addr = a;
                        if (r->ttl != ttl) {
                            if (r->ttl == 0) {
                                r->ttl = ttl;
                            } else {
                                mdns_priv_query_update_result_ttl(r, ttl);
                            }
                        }
                        if (add_browse_result(out_sync_browse, r) != ESP_OK) {
                            return;
                        }
                        break;
                    }
                }
            }
            r = r->next;
        }
    }
}

static bool txt_values_equal(const char *a, const char *b, uint8_t len)
{
    if (len == 0) {
        return true;
    }
    if (!a || !b) {
        return a == b;
    }
    return memcmp(a, b, len) == 0;
}

static bool is_txt_item_in_list(mdns_txt_item_t txt, uint8_t txt_value_len, mdns_txt_item_t *txt_list, uint8_t *txt_value_len_list, size_t txt_count)
{
    for (size_t i = 0; i < txt_count; i++) {
        if (mdns_utils_str_null_or_empty(txt.key) || mdns_utils_str_null_or_empty(txt_list[i].key)) {
            if (mdns_utils_str_null_or_empty(txt.key) != mdns_utils_str_null_or_empty(txt_list[i].key)) {
                continue;
            }
        } else if (strcmp(txt.key, txt_list[i].key) != 0) {
            continue;
        }
        if (txt_value_len != txt_value_len_list[i]) {
            return false;
        }
        if (txt_values_equal(txt.value, txt_list[i].value, txt_value_len)) {
            return true;
        }
        // The key value is unique, so there is no need to continue searching.
        return false;
    }
    return false;
}

/**
 * @brief  Called from parser to add TXT data to search result
 */
void mdns_priv_browse_result_add_txt(mdns_browse_t *browse, const char *instance, const char *service, const char *proto,
                                     mdns_txt_item_t *txt, uint8_t *txt_value_len, size_t txt_count, mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol,
                                     uint32_t ttl, mdns_browse_sync_t *out_sync_browse)
{
    if (out_sync_browse->browse == NULL || out_sync_browse->browse != browse
            || mdns_utils_str_null_or_empty(instance) || mdns_utils_str_null_or_empty(service)
            || mdns_utils_str_null_or_empty(proto)) {
        goto free_txt;
    }
    mdns_result_t *r = browse->result;
    while (r) {
        if (r->esp_netif == mdns_priv_get_esp_netif(tcpip_if) && r->ip_protocol == ip_protocol &&
                !mdns_utils_str_null_or_empty(r->instance_name) && !strcasecmp(instance, r->instance_name) &&
                !mdns_utils_str_null_or_empty(r->service_type) && !strcasecmp(service, r->service_type) &&
                !mdns_utils_str_null_or_empty(r->proto) && !strcasecmp(proto, r->proto)) {
            bool should_update = false;
            if (r->txt) {
                // Check if txt changed
                if (txt_count != r->txt_count) {
                    should_update = true;
                } else {
                    for (size_t txt_index = 0; txt_index < txt_count; txt_index++) {
                        if (!is_txt_item_in_list(txt[txt_index], txt_value_len[txt_index], r->txt, r->txt_value_len, r->txt_count)) {
                            should_update = true;
                            break;
                        }
                    }
                }
                // If the result has a previous txt entry, we delete it and re-add.
                for (size_t i = 0; i < r->txt_count; i++) {
                    mdns_mem_free((char *)(r->txt[i].key));
                    mdns_mem_free((char *)(r->txt[i].value));
                }
                mdns_mem_free(r->txt);
                mdns_mem_free(r->txt_value_len);
            }
            r->txt = txt;
            r->txt_value_len = txt_value_len;
            r->txt_count = txt_count;
            if (r->ttl != ttl) {
                uint32_t previous_ttl = r->ttl;
                if (r->ttl == 0) {
                    r->ttl = ttl;
                } else {
                    mdns_priv_query_update_result_ttl(r, ttl);
                }
                if (previous_ttl != r->ttl) {
                    should_update = true;
                }
            }
            if (should_update) {
                if (add_browse_result(out_sync_browse, r) != ESP_OK) {
                    return;
                }
            }
            return;
        }
        r = r->next;
    }
    r = (mdns_result_t *)mdns_mem_malloc(sizeof(mdns_result_t));
    if (!r) {
        HOOK_MALLOC_FAILED;
        goto free_txt;
    }
    memset(r, 0, sizeof(mdns_result_t));
    r->instance_name = mdns_mem_strdup(instance);
    r->service_type = mdns_mem_strdup(service);
    r->proto = mdns_mem_strdup(proto);
    if (!r->instance_name || !r->service_type || !r->proto) {
        HOOK_MALLOC_FAILED;
        mdns_mem_free(r->instance_name);
        mdns_mem_free(r->service_type);
        mdns_mem_free(r->proto);
        mdns_mem_free(r);
        goto free_txt;
    }
    r->txt = txt;
    r->txt_value_len = txt_value_len;
    r->txt_count = txt_count;
    r->esp_netif = mdns_priv_get_esp_netif(tcpip_if);
    r->ip_protocol = ip_protocol;
    r->ttl = ttl;
    r->next = browse->result;
    browse->result = r;
    add_browse_result(out_sync_browse, r);
    return;

free_txt:
    for (size_t i = 0; i < txt_count; i++) {
        mdns_mem_free((char *)(txt[i].key));
        mdns_mem_free((char *)(txt[i].value));
    }
    mdns_mem_free(txt);
    mdns_mem_free(txt_value_len);
    return;
}

static esp_err_t copy_address_in_previous_result(mdns_result_t *result_list, mdns_result_t *r)
{
    while (result_list) {
        if (!mdns_utils_str_null_or_empty(result_list->hostname) && !mdns_utils_str_null_or_empty(r->hostname) && !strcasecmp(result_list->hostname, r->hostname) &&
                result_list->ip_protocol == r->ip_protocol && result_list->addr && !r->addr) {
            // If there is a same hostname in previous result, we need to copy the address here.
            r->addr = mdns_utils_copy_address_list(result_list->addr);
            if (!r->addr) {
                return ESP_ERR_NO_MEM;
            }
            break;
        } else {
            result_list = result_list->next;
        }
    }
    return ESP_OK;
}

/**
 * @brief  Called from parser to add SRV data to search result
 */
void mdns_priv_browse_result_add_srv(mdns_browse_t *browse, const char *hostname, const char *instance, const char *service, const char *proto,
                                     uint16_t port, mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol, uint32_t ttl, mdns_browse_sync_t *out_sync_browse)
{
    if (out_sync_browse->browse == NULL) {
        return;
    } else {
        if (out_sync_browse->browse != browse) {
            return;
        }
    }
    if (mdns_utils_str_null_or_empty(instance) || mdns_utils_str_null_or_empty(service)
            || mdns_utils_str_null_or_empty(proto)) {
        return;
    }
    mdns_result_t *r = browse->result;
    while (r) {
        if (r->esp_netif == mdns_priv_get_esp_netif(tcpip_if) && r->ip_protocol == ip_protocol &&
                !mdns_utils_str_null_or_empty(r->instance_name) && !strcasecmp(instance, r->instance_name) &&
                !mdns_utils_str_null_or_empty(r->service_type) && !strcasecmp(service, r->service_type) &&
                !mdns_utils_str_null_or_empty(r->proto) && !strcasecmp(proto, r->proto)) {
            if (mdns_utils_str_null_or_empty(r->hostname)
                    || mdns_utils_str_null_or_empty(hostname)
                    || strcasecmp(hostname, r->hostname)) {
                mdns_mem_free((char *)r->hostname);
                r->hostname = mdns_mem_strdup(hostname);
                r->port = port;
                if (!r->hostname) {
                    HOOK_MALLOC_FAILED;
                    return;
                }
                if (!r->addr) {
                    esp_err_t err = copy_address_in_previous_result(browse->result, r);
                    if (err == ESP_ERR_NO_MEM) {
                        return;
                    }
                }
                if (add_browse_result(out_sync_browse, r) != ESP_OK) {
                    return;
                }
            }
            if (r->ttl != ttl) {
                uint32_t previous_ttl = r->ttl;
                if (r->ttl == 0) {
                    r->ttl = ttl;
                } else {
                    mdns_priv_query_update_result_ttl(r, ttl);
                }
                if (previous_ttl != r->ttl) {
                    if (add_browse_result(out_sync_browse, r) != ESP_OK) {
                        return;
                    }
                }
            }
            return;
        }
        r = r->next;
    }
    r = (mdns_result_t *)mdns_mem_malloc(sizeof(mdns_result_t));
    if (!r) {
        HOOK_MALLOC_FAILED;
        return;
    }

    memset(r, 0, sizeof(mdns_result_t));
    r->hostname = mdns_mem_strdup(hostname);
    r->instance_name = mdns_mem_strdup(instance);
    r->service_type = mdns_mem_strdup(service);
    r->proto = mdns_mem_strdup(proto);
    if (!r->hostname || !r->instance_name || !r->service_type || !r->proto) {
        HOOK_MALLOC_FAILED;
        mdns_mem_free(r->hostname);
        mdns_mem_free(r->instance_name);
        mdns_mem_free(r->service_type);
        mdns_mem_free(r->proto);
        mdns_mem_free(r);
        return;
    }
    r->port = port;
    r->esp_netif = mdns_priv_get_esp_netif(tcpip_if);
    r->ip_protocol = ip_protocol;
    r->ttl = ttl;
    r->next = browse->result;
    browse->result = r;
    add_browse_result(out_sync_browse, r);
}

/**
 * @brief  Browse sync result
 */
esp_err_t mdns_priv_browse_sync(mdns_browse_sync_t *browse_sync)
{
    mdns_action_t *action = NULL;

    action = (mdns_action_t *)mdns_mem_malloc(sizeof(mdns_action_t));
    if (!action) {
        HOOK_MALLOC_FAILED;
        return ESP_ERR_NO_MEM;
    }

    action->type = ACTION_BROWSE_SYNC;
    action->data.browse_sync.browse_sync = browse_sync;
    if (!mdns_priv_queue_action(action)) {
        mdns_mem_free(action);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static bool service_cache_has_subtype(const mdns_service_cache_t *service, const char *subtype)
{
    if (!service || mdns_utils_str_null_or_empty(subtype)) {
        return false;
    }

    for (const mdns_cache_subtype_t *subtype_list = service->subtype_list; subtype_list; subtype_list = subtype_list->next) {
        if (!mdns_utils_str_null_or_empty(subtype_list->subtype) && !strcasecmp(subtype_list->subtype, subtype)) {
            return true;
        }
    }

    return false;
}

static bool service_cache_matches_browse(const mdns_service_cache_t *service, const mdns_browse_t *browse)
{
    if (!service || !browse || browse->state != BROWSE_RUNNING || !browse->notifier
            || mdns_utils_str_null_or_empty(browse->service) || mdns_utils_str_null_or_empty(browse->proto)
            || strcasecmp(service->service, browse->service) || strcasecmp(service->proto, browse->proto)) {
        return false;
    }

    if (mdns_utils_str_null_or_empty(browse->subtype)) {
        return service->ptr_present;
    }

    return service_cache_has_subtype(service, browse->subtype);
}

static bool browse_result_matches_service_cache(const mdns_result_t *result, const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    return result && result->esp_netif == entry->esp_netif && result->ip_protocol == entry->ip_protocol
           && result->instance_name && result->service_type && result->proto
           && !strcasecmp(result->instance_name, service->instance_name)
           && !strcasecmp(result->service_type, service->service)
           && !strcasecmp(result->proto, service->proto);
}

static mdns_result_t **browse_find_result(mdns_browse_t *browse, const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    mdns_result_t **link = &browse->result;
    while (*link) {
        if (browse_result_matches_service_cache(*link, entry, service)) {
            return link;
        }
        link = &(*link)->next;
    }
    return link;
}

static void browse_replace_result(mdns_result_t **link, mdns_result_t *new_result)
{
    mdns_result_t *old_result = *link;

    if (old_result) {
        new_result->next = old_result->next;
        *link = new_result;

        old_result->next = NULL;
        mdns_priv_query_results_free(old_result);
    } else {
        new_result->next = NULL;
        *link = new_result;
    }
}

static bool update_browse_result(mdns_browse_t *browse, const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    mdns_result_t *new_result = mdns_priv_service_cache_to_result(entry, service);
    if (!new_result) {
        return false;
    }

    mdns_browse_sync_t *sync_browse = mdns_priv_browse_ensure_sync(browse, NULL);
    if (!sync_browse) {
        mdns_priv_query_results_free(new_result);
        return false;
    }

    if (add_browse_result(sync_browse, new_result) != ESP_OK) {
        mdns_priv_query_results_free(new_result);
        mdns_priv_browse_sync_free(sync_browse);
        return false;
    }

    mdns_result_t **link = browse_find_result(browse, entry, service);
    browse_replace_result(link, new_result);
    ESP_LOGI(TAG, "Browse result updated: %s, %s, %s", browse->service, browse->proto, browse->subtype);

    if (mdns_priv_browse_sync(sync_browse) != ESP_OK) {
        mdns_priv_browse_sync_free(sync_browse);
        return false;
    }

    return true;
}

bool mdns_priv_browse_update_from_service_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    bool updated = true;

    if (!entry || !service) {
        return false;
    }

    // Update all browsers matching service.proto, without subtype
    for (mdns_browse_t *browse = s_browse; browse; browse = browse->next) {
        if (service_cache_matches_browse(service, browse)) {
            updated &= update_browse_result(browse, entry, service);
        }
    }
    return updated;
}

static void browse_remove_results_from_service_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                                     const char *subtype, bool remove_all)
{
    if (!entry || !service) {
        return;
    }

    for (mdns_browse_t *browse = s_browse; browse; browse = browse->next) {
        if (browse->state != BROWSE_RUNNING || !browse->notifier
                || mdns_utils_str_null_or_empty(browse->service) || mdns_utils_str_null_or_empty(browse->proto)
                || strcasecmp(browse->service, service->service) || strcasecmp(browse->proto, service->proto)) {
            continue;
        }

        if (!remove_all) {
            if (mdns_utils_str_null_or_empty(subtype)) {
                // PTR goodbye: only removes non-subtype browse
                if (!mdns_utils_str_null_or_empty(browse->subtype)) {
                    continue;
                }
            } else {
                // Subtype PTR goodbye: only removes browse with identical subtype
                if (mdns_utils_str_null_or_empty(browse->subtype) || strcasecmp(browse->subtype, subtype)) {
                    continue;
                }
            }
        }

        mdns_result_t **result_link = browse_find_result(browse, entry, service);
        mdns_result_t *result = *result_link;
        if (!result || result->ttl == 0) {
            continue;
        }

        mdns_browse_sync_t *sync_browse = mdns_priv_browse_ensure_sync(browse, NULL);
        if (!sync_browse) {
            continue;
        }

        if (add_browse_result(sync_browse, result) != ESP_OK) {
            mdns_priv_browse_sync_free(sync_browse);
            continue;
        }

        uint32_t previous_ttl = result->ttl;
        result->ttl = 0;
        ESP_LOGI(TAG, "Browse result removed: %s, %s, %s", browse->service, browse->proto, browse->subtype);
        if (mdns_priv_browse_sync(sync_browse) != ESP_OK) {
            result->ttl = previous_ttl;
            mdns_priv_browse_sync_free(sync_browse);
        }
    }
}

void mdns_priv_browse_remove_result_from_service_cache(const mdns_cache_entry_t *entry,
                                                       const mdns_service_cache_t *service,
                                                       const char *subtype)
{
    browse_remove_results_from_service_cache(entry, service, subtype, false);
}

void mdns_priv_browse_remove_all_results_from_service_cache(const mdns_cache_entry_t *entry,
                                                            const mdns_service_cache_t *service)
{
    browse_remove_results_from_service_cache(entry, service, NULL, true);
}

/**
 * @defgroup MDNS_PUBCLIC_API
 */
mdns_browse_t *mdns_browse_new(const char *service, const char *proto, mdns_browse_notify_t notifier)
{
    return mdns_browse_new_with_subtype(service, proto, NULL, notifier);
}

mdns_browse_t *mdns_browse_new_with_subtype(const char *service, const char *proto, const char *subtype, mdns_browse_notify_t notifier)
{
    mdns_browse_t *browse = NULL;

    if (!mdns_priv_is_server_init() || mdns_utils_str_null_or_empty(service) || mdns_utils_str_null_or_empty(proto)) {
        return NULL;
    }

    browse = browse_init(service, proto, subtype, notifier);
    if (!browse) {
        return NULL;
    }

    if (send_browse_action(ACTION_BROWSE_ADD, browse)) {
        browse_item_free(browse);
        return NULL;
    }

    return browse;
}

esp_err_t mdns_browse_delete(const char *service, const char *proto)
{
    return mdns_browse_delete_with_subtype(service, proto, NULL);
}

esp_err_t mdns_browse_delete_with_subtype(const char *service, const char *proto, const char *subtype)
{
    mdns_browse_t *browse = NULL;

    if (!mdns_priv_is_server_init() || mdns_utils_str_null_or_empty(service) || mdns_utils_str_null_or_empty(proto)) {
        return ESP_FAIL;
    }

    browse = browse_init(service, proto, subtype, NULL);
    if (!browse) {
        return ESP_ERR_NO_MEM;
    }

    if (send_browse_action(ACTION_BROWSE_END, browse)) {
        browse_item_free(browse);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
