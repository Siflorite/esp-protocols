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
    if (!browse) {
        return;
    }

    mdns_mem_free(browse->service);
    mdns_mem_free(browse->proto);
    mdns_mem_free(browse->subtype);
    mdns_mem_free(browse);
}

/**
 * @brief Deliver browse updates to the user notifier
 *
 * Invokes the notifier once per changed result accumulated for the current
 * packet. The passed @c result pointer is a temporary projection of the internal mDNS cache,
 * which is only valid during the lifetime of this callback and is freed immediately after the callback returns.
 */
static void browse_sync(mdns_browse_sync_t *browse_sync)
{
    mdns_browse_t *browse = browse_sync->browse;

    for (mdns_browse_result_sync_t *sync_result = browse_sync->sync_result; sync_result; sync_result = sync_result->next) {
        mdns_result_t *result = sync_result->result;
        DBG_BROWSE_RESULTS(result, browse_sync->browse);

        if (browse->notifier) {
            browse->notifier(result);
        }

        result->next = NULL;
        mdns_priv_query_results_free(result);
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

/**
 * @brief Check if two browses are the same.
 *        Compare service, proto, and possible subtype.
 */
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

/**
 * @brief Check if a browse `_service._proto` is running.
 */
static bool browse_has_service(const char *service, const char *proto)
{
    for (const mdns_browse_t *it = s_browse; it; it = it->next) {
        if (it->state == BROWSE_RUNNING && !mdns_utils_str_null_or_empty(it->service)
                && !mdns_utils_str_null_or_empty(it->proto) && !strcasecmp(service, it->service)
                && !strcasecmp(proto, it->proto)) {
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

    for (mdns_browse_t *it = s_browse; it; it = it->next) {
        if (browse_match(it, browse)) {
            queueDetach(mdns_browse_t, s_browse, it);
            browse_item_free(it);
            removed = true;
            break;
        }
    }

    if (removed) {
        if (!browse_has_service(browse->service, browse->proto)) {
            mdns_priv_remove_service_caches(browse->service, browse->proto);
        } else if (!mdns_utils_str_null_or_empty(browse->subtype)) {
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

    for (mdns_browse_t *it = s_browse; it; it = it->next) {
        if (browse_match(it, browse)) {
            ESP_LOGW(TAG, "Browse already exists: %s, %s, %s", browse->service, browse->proto, browse->subtype);
            browse_item_free(browse);
            return;
        }
    }

    browse->next = s_browse;
    s_browse = browse;

    if (!mdns_priv_cache_notify_browse(browse)) {
        ESP_LOGW(TAG, "Failed to notify all cached results for %s.%s", browse->service, browse->proto);
    }

    for (uint8_t interface_idx = 0; interface_idx < MDNS_MAX_INTERFACES; interface_idx++) {
        for (uint8_t protocol_idx = 0; protocol_idx < MDNS_IP_PROTOCOL_MAX; protocol_idx++) {
            browse_send(browse, (mdns_if_t) interface_idx, (mdns_ip_protocol_t) protocol_idx);
        }
    }
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
            if (mdns_priv_host_has_service(name->host, mdns_priv_get_esp_netif(tcpip_if),
                                           ip_protocol, b->service, b->proto)) {
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

    while (current) {
        mdns_browse_result_sync_t *next = current->next;
        mdns_mem_free(current);
        current = next;
    }

    mdns_mem_free(browse_sync);
}

void mdns_priv_browse_sync_free(mdns_browse_sync_t *browse_sync)
{
    if (!browse_sync) {
        return;
    }

    for (mdns_browse_result_sync_t *sync_result = browse_sync->sync_result; sync_result; sync_result = sync_result->next) {
        mdns_priv_query_results_free(sync_result->result);
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
            // free the sync linked list and result components
            mdns_priv_browse_sync_free(action->data.browse_sync.browse_sync);
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
        mdns_browse_result_sync_t *new =
            (mdns_browse_result_sync_t *)mdns_mem_malloc(sizeof(mdns_browse_result_sync_t));

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

/**
 * @brief Check if a running browse `_service._proto` matches a service cache `_service._proto`.
 */
static bool browse_matches_service_cache(const mdns_browse_t *browse, const mdns_service_cache_t *service)
{
    return browse && service && browse->state == BROWSE_RUNNING && browse->notifier
           && !mdns_utils_str_null_or_empty(browse->service)
           && !mdns_utils_str_null_or_empty(browse->proto)
           && !mdns_utils_str_null_or_empty(service->service)
           && !mdns_utils_str_null_or_empty(service->proto)
           && !strcasecmp(browse->service, service->service)
           && !strcasecmp(browse->proto, service->proto);
}

/**
 * @brief Check if a service cache has a specific subtype.
 */
static bool service_cache_has_subtype(const mdns_service_cache_t *service, const char *subtype)
{
    if (!service || mdns_utils_str_null_or_empty(subtype)) {
        return false;
    }

    for (const mdns_cache_subtype_t *it = service->subtype_list; it; it = it->next) {
        if (!mdns_utils_str_null_or_empty(it->subtype) && !strcasecmp(it->subtype, subtype)) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Check if a running browse matches a service cache with service name, proto, and possible subtype.
 */
static bool browse_matches_service_cache_with_subtype(const mdns_browse_t *browse, const mdns_service_cache_t *service)
{
    if (!browse_matches_service_cache(browse, service)) {
        return false;
    }

    if (mdns_utils_str_null_or_empty(browse->subtype)) {
        return service->ptr_present;
    }

    return service_cache_has_subtype(service, browse->subtype);
}

/**
 * @brief Build and sync a temporary result for a browse from cache.
 */
static bool browse_build_and_sync_temp_result(mdns_browse_t *browse, const mdns_cache_entry_t *entry,
                                              const mdns_service_cache_t *service, bool goodbye)
{
    mdns_result_t *result = mdns_priv_service_cache_to_result(entry, service);
    if (!result) {
        return false;
    }

    if (!mdns_utils_str_null_or_empty(browse->subtype)) {
        result->subtype = mdns_mem_strdup(browse->subtype);
        if (!result->subtype) {
            HOOK_MALLOC_FAILED;
            mdns_priv_query_results_free(result);
            return false;
        }
    }

    result->next = NULL;
    if (goodbye) {
        result->ttl = 0;
    }

    mdns_browse_sync_t *browse_sync = mdns_priv_browse_ensure_sync(browse, NULL);
    if (!browse_sync) {
        mdns_priv_query_results_free(result);
        return false;
    }

    if (add_browse_result(browse_sync, result) != ESP_OK) {
        mdns_priv_query_results_free(result);
        mdns_priv_browse_sync_free(browse_sync);
        return false;
    }

    if (mdns_priv_browse_sync(browse_sync) != ESP_OK) {
        mdns_priv_browse_sync_free(browse_sync);
        return false;
    }

    return true;
}

bool mdns_priv_browse_update_from_service_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    if (!entry || !service) {
        return false;
    }

    bool updated = true;

    for (mdns_browse_t *browse = s_browse; browse; browse = browse->next) {
        if (browse_matches_service_cache_with_subtype(browse, service)) {
            updated &= browse_build_and_sync_temp_result(browse, entry, service, false);
        }
    }

    return updated;
}

bool mdns_priv_browse_notify_from_service_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                                mdns_browse_t *browse)
{
    if (!entry || !service || !browse) {
        return false;
    }

    if (!browse_matches_service_cache_with_subtype(browse, service)) {
        return true;
    }

    return browse_build_and_sync_temp_result(browse, entry, service, false);
}

bool mdns_priv_browse_notify_ptr_goodbye_from_service_cache(const mdns_cache_entry_t *entry,
                                                            const mdns_service_cache_t *service,
                                                            const char *subtype)
{
    if (!entry || !service) {
        return false;
    }

    bool notified = true;

    for (mdns_browse_t *browse = s_browse; browse; browse = browse->next) {
        if (!browse_matches_service_cache_with_subtype(browse, service)) {
            continue;
        }

        if (mdns_utils_str_null_or_empty(subtype)) {
            if (!mdns_utils_str_null_or_empty(browse->subtype)) {
                continue;
            }
        } else {
            if (mdns_utils_str_null_or_empty(browse->subtype) || strcasecmp(browse->subtype, subtype)) {
                continue;
            }
        }

        notified &= browse_build_and_sync_temp_result(browse, entry, service, true);
    }

    return notified;
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
