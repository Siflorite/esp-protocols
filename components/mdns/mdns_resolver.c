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
#include "mdns_resolver.h"
#include "mdns_responder.h"
#include "mdns_service.h"
#include "mdns_utils.h"

static const char *TAG = "mdns_resolver";

static mdns_resolver_t *s_resolver;

static inline bool names_equal(const char *a, const char *b)
{
    return !mdns_utils_str_null_or_empty(a) && !mdns_utils_str_null_or_empty(b) && strcasecmp(a, b) == 0;
}

static inline mdns_cache_record_type_t resolver_type_to_record_type(mdns_resolver_type_t type)
{
    switch (type) {
    case MDNS_RESOLVER_TYPE_SRV:
        return MDNS_CACHE_RECORD_SRV;
    default:
        return 0;
    }
}

static bool resolvers_match(const mdns_resolver_t *a, const mdns_resolver_t *b)
{
    if (!a || !b || a->type != b->type) {
        return false;
    }

    switch (a->type) {
    case MDNS_RESOLVER_TYPE_SRV:
        return names_equal(a->instance_name, b->instance_name)
               && names_equal(a->service, b->service)
               && names_equal(a->proto, b->proto);
    default:
        return false;
    }
}

static bool resolver_exists(const mdns_resolver_t *resolver)
{
    for (const mdns_resolver_t *it = s_resolver; it; it = it->next) {
        if (it == resolver) {
            return true;
        }
    }
    return false;
}

static bool resolver_matches_service_cache(const mdns_resolver_t *resolver, const mdns_cache_entry_t *entry, const mdns_service_cache_t *service)
{
    if (resolver && entry && service && resolver->state == RESOLVER_RUNNING) {
        switch (resolver->type) {
        case MDNS_RESOLVER_TYPE_SRV:
            return service->srv_present && resolver->notifier.srv
                   && names_equal(resolver->instance_name, service->instance_name)
                   && names_equal(resolver->service, service->service)
                   && names_equal(resolver->proto, service->proto);
        default:
            ESP_LOGE(TAG, "Invalid resolver type: %d", resolver->type);
            return false;
        }
    }
    return false;
}

static void resolver_item_free(mdns_resolver_t *resolver)
{
    if (!resolver) {
        return;
    }

    mdns_mem_free(resolver->instance_name);
    mdns_mem_free(resolver->service);
    mdns_mem_free(resolver->proto);
    mdns_mem_free(resolver);
}

void mdns_priv_resolver_free(void)
{
    while (s_resolver) {
        mdns_resolver_t *resolver = s_resolver;
        s_resolver = resolver->next;
        resolver_item_free(resolver);
    }
    s_resolver = NULL;
}

static void resolver_send_question(char *instance_name, char *service, char *proto, uint16_t record_type,
                                   mdns_if_t mdns_if, mdns_ip_protocol_t ip_protocol)
{
    mdns_search_once_t search = {
        .instance = instance_name,
        .service = service,
        .proto = proto,
        .type = record_type,
        .unicast = true,
    };
    mdns_priv_query_send(&search, mdns_if, ip_protocol);
}

static void resolver_send(mdns_resolver_t *resolver, mdns_if_t mdns_if, mdns_ip_protocol_t ip_protocol)
{
    if (!resolver || resolver->state != RESOLVER_RUNNING) {
        return;
    }

    uint16_t record_type = 0;
    switch (resolver->type) {
    case MDNS_RESOLVER_TYPE_SRV:
        record_type = MDNS_TYPE_SRV;
        break;
    default:
        ESP_LOGE(TAG, "Invalid resolver type: %d", resolver->type);
        return;
    }

    resolver_send_question(resolver->instance_name, resolver->service, resolver->proto, record_type, mdns_if, ip_protocol);
}

static mdns_resolver_t *resolver_init(const char *instance_name, const char *service, const char *proto,
                                      mdns_resolver_type_t type)
{
    mdns_resolver_t *resolver = (mdns_resolver_t *)mdns_mem_calloc(1, sizeof(mdns_resolver_t));
    if (!resolver) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }

    resolver->type = type;
    resolver->state = RESOLVER_INIT;

    if (!mdns_utils_str_null_or_empty(instance_name)) {
        resolver->instance_name = mdns_mem_strndup(instance_name, MDNS_NAME_MAX_LEN);
        if (!resolver->instance_name) {
            HOOK_MALLOC_FAILED;
            resolver_item_free(resolver);
            return NULL;
        }
    }

    if (!mdns_utils_str_null_or_empty(service)) {
        resolver->service = mdns_mem_strndup(service, MDNS_NAME_MAX_LEN);
        if (!resolver->service) {
            HOOK_MALLOC_FAILED;
            resolver_item_free(resolver);
            return NULL;
        }
    }

    if (!mdns_utils_str_null_or_empty(proto)) {
        resolver->proto = mdns_mem_strndup(proto, MDNS_NAME_MAX_LEN);
        if (!resolver->proto) {
            HOOK_MALLOC_FAILED;
            resolver_item_free(resolver);
            return NULL;
        }
    }

    return resolver;
}

static void resolver_start(mdns_resolver_t *resolver)
{
    if (!resolver || resolver->state != RESOLVER_INIT) {
        return;
    }
    resolver->state = RESOLVER_RUNNING;
    (void)mdns_priv_cache_notify_resolver(resolver);
    for (uint8_t interface_idx = 0; interface_idx < MDNS_MAX_INTERFACES; interface_idx++) {
        for (uint8_t protocol_idx = 0; protocol_idx < MDNS_IP_PROTOCOL_MAX; protocol_idx++) {
            resolver_send(resolver, (mdns_if_t) interface_idx, (mdns_ip_protocol_t) protocol_idx);
        }
    }
}

static void resolver_finish(mdns_resolver_t *resolver)
{
    if (!resolver_exists(resolver)) {
        return;
    }

    resolver->state = RESOLVER_OFF;
    queueDetach(mdns_resolver_t, s_resolver, resolver);

    if (!mdns_utils_str_null_or_empty(resolver->instance_name) && !mdns_utils_str_null_or_empty(resolver->service)
            && !mdns_utils_str_null_or_empty(resolver->proto)) {
        mdns_priv_cache_remove_service_cache_if_unused(resolver->instance_name, resolver->service, resolver->proto);
    }

    resolver_item_free(resolver);
}

static esp_err_t send_resolver_action(mdns_action_type_t type, mdns_resolver_t *resolver)
{
    mdns_action_t *action = (mdns_action_t *)mdns_mem_malloc(sizeof(mdns_action_t));
    if (!action) {
        HOOK_MALLOC_FAILED;
        return ESP_ERR_NO_MEM;
    }

    action->type = type;
    action->data.resolver_add_end.resolver = resolver;

    if (!mdns_priv_queue_action(action)) {
        mdns_mem_free(action);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static mdns_srv_resolver_result_t *build_srv_result(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                                    bool goodbye)
{
    if (!entry || !service || !service->srv_present || mdns_utils_str_null_or_empty(entry->hostname)) {
        return NULL;
    }

    mdns_srv_resolver_result_t *result = (mdns_srv_resolver_result_t *)mdns_mem_calloc(1, sizeof(mdns_srv_resolver_result_t));
    if (!result) {
        HOOK_MALLOC_FAILED;
        return NULL;
    }

    result->esp_netif = entry->esp_netif;
    result->ip_protocol = entry->ip_protocol;

    result->instance_name = mdns_mem_strdup(service->instance_name);
    if (!result->instance_name) {
        HOOK_MALLOC_FAILED;
        mdns_srv_resolver_result_free(result);
        return NULL;
    }

    result->service_type = mdns_mem_strdup(service->service);
    if (!result->service_type) {
        HOOK_MALLOC_FAILED;
        mdns_srv_resolver_result_free(result);
        return NULL;
    }

    result->proto = mdns_mem_strdup(service->proto);
    if (!result->proto) {
        HOOK_MALLOC_FAILED;
        mdns_srv_resolver_result_free(result);
        return NULL;
    }

    result->hostname = mdns_mem_strdup(entry->hostname);
    if (!result->hostname) {
        HOOK_MALLOC_FAILED;
        mdns_srv_resolver_result_free(result);
        return NULL;
    }

    result->priority = service->priority;
    result->weight = service->weight;
    result->port = service->port;
    result->ttl = goodbye ? 0 : service->srv_ttl;

    return result;
}

static bool resolver_notify(mdns_resolver_t *resolver, const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                            bool goodbye)
{
    if (!resolver || !entry || !service) {
        return false;
    }

    switch (resolver->type) {
    case MDNS_RESOLVER_TYPE_SRV:
        if (!resolver->notifier.srv) {
            return false;
        }

        mdns_srv_resolver_result_t *result = build_srv_result(entry, service, goodbye);
        if (!result) {
            return false;
        }

        resolver->notifier.srv(result);
        return true;
    default:
        ESP_LOGE(TAG, "Invalid resolver type: %d", resolver->type);
        return false;
    }

    return false;
}

void mdns_priv_resolver_action(mdns_action_t *action, mdns_action_subtype_t type)
{
    if (type == ACTION_RUN) {
        switch (action->type) {
        case ACTION_RESOLVER_START:
            resolver_start(action->data.resolver_add_end.resolver);
            break;
        case ACTION_RESOLVER_END:
            resolver_finish(action->data.resolver_add_end.resolver);
            break;
        default:
            abort();
        }
    } else if (type == ACTION_CLEANUP) {
        switch (action->type) {
        case ACTION_RESOLVER_START:
        case ACTION_RESOLVER_END:
            // Resolver actions do not own the resolver. If a queued action is
            // discarded during shutdown, the linked resolver is released by
            // mdns_priv_resolver_free().
            break;
        default:
            abort();
        }
    }
}

void mdns_priv_resolver_send_by_ip_protocol(mdns_if_t mdns_if, mdns_ip_protocol_t ip_protocol)
{
    for (mdns_resolver_t *it = s_resolver; it; it = it->next) {
        resolver_send(it, mdns_if, ip_protocol);
    }
}

bool mdns_priv_resolver_has_service(const char *instance_name, const char *service, const char *proto)
{
    for (mdns_resolver_t *it = s_resolver; it; it = it->next) {
        if (it->state != RESOLVER_OFF && names_equal(it->instance_name, instance_name)
                && names_equal(it->service, service) && names_equal(it->proto, proto)) {
            return true;
        }
    }
    return false;
}

mdns_resolver_t *mdns_priv_resolver_find(const char *instance_name, const char *service, const char *proto,
                                         mdns_resolver_type_t type)
{
    for (mdns_resolver_t *it = s_resolver; it; it = it->next) {
        if (it->type != type || it->state != RESOLVER_RUNNING) {
            continue;
        }

        switch (type) {
        case MDNS_RESOLVER_TYPE_SRV:
            if (names_equal(it->instance_name, instance_name) && names_equal(it->service, service)
                    && names_equal(it->proto, proto)) {
                return it;
            }
            break;
        default:
            ESP_LOGE(TAG, "Invalid resolver type: %d", it->type);
            break;
        }
    }
    return NULL;
}

mdns_cache_record_mask_t mdns_priv_resolver_update_from_service_cache(const mdns_cache_entry_t *entry,
                                                                      const mdns_service_cache_t *service,
                                                                      mdns_cache_record_mask_t record_mask)
{
    mdns_cache_record_mask_t completed_records = record_mask;

    if (!entry || !service) {
        return 0;
    }

    for (mdns_resolver_t *resolver = s_resolver; resolver; resolver = resolver->next) {
        mdns_cache_record_type_t record_type = resolver_type_to_record_type(resolver->type);
        // Checks if the cache in resolver's record type is to be synced.
        if (!(record_mask & (mdns_cache_record_mask_t)record_type)) {
            continue;
        }
        // Checks if the resolver matches the service cache.
        if (!resolver_matches_service_cache(resolver, entry, service)) {
            continue;
        }
        // If failed to notify, the record is not completed.
        if (!resolver_notify(resolver, entry, service, false)) {
            completed_records &= ~(mdns_cache_record_mask_t)record_type;
        }
    }

    return completed_records;
}

bool mdns_priv_resolver_notify_from_service_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                                  mdns_resolver_t *resolver)
{
    if (!entry || !service || !resolver || resolver->state != RESOLVER_RUNNING) {
        return false;
    }

    if (!resolver_matches_service_cache(resolver, entry, service)) {
        return true;
    }

    return resolver_notify(resolver, entry, service, false);
}

bool mdns_priv_resolver_notify_goodbye_from_service_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                                          mdns_cache_record_mask_t record_mask)
{
    bool notified = true;

    if (!entry || !service) {
        return false;
    }

    for (mdns_resolver_t *resolver = s_resolver; resolver; resolver = resolver->next) {
        // Checks if the cache in resolver's record type is to be notified.
        mdns_cache_record_type_t record_type = resolver_type_to_record_type(resolver->type);
        if (!(record_mask & (mdns_cache_record_mask_t)record_type)) {
            continue;
        }
        // Checks if the resolver matches the service cache.
        if (!resolver_matches_service_cache(resolver, entry, service)) {
            continue;
        }

        notified &= resolver_notify(resolver, entry, service, true);
    }

    return notified;
}

/**
 * @defgroup MDNS_PUBCLIC_API
 */
mdns_resolver_t *mdns_srv_resolver_new(const char *instance_name, const char *service, const char *proto,
                                       mdns_srv_resolver_notify_t notifier)
{
    mdns_resolver_t *resolver = NULL;

    if (!mdns_priv_is_server_init() || !notifier || mdns_utils_str_null_or_empty(instance_name)
            || mdns_utils_str_null_or_empty(service) || mdns_utils_str_null_or_empty(proto)) {
        return NULL;
    }

    resolver = resolver_init(instance_name, service, proto, MDNS_RESOLVER_TYPE_SRV);
    if (!resolver) {
        return NULL;
    }

    resolver->notifier.srv = notifier;

    mdns_priv_service_lock();

    for (mdns_resolver_t *it = s_resolver; it; it = it->next) {
        if (it->state != RESOLVER_OFF && resolvers_match(it, resolver)) {
            ESP_LOGW(TAG, "Resolver already exists: %s, %s, %s", resolver->instance_name, resolver->service, resolver->proto);
            goto error;
        }
    }

    if (send_resolver_action(ACTION_RESOLVER_START, resolver) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send resolver start action");
        goto error;
    }

    resolver->next = s_resolver;
    s_resolver = resolver;

    mdns_priv_service_unlock();
    return resolver;

error:
    mdns_priv_service_unlock();
    resolver_item_free(resolver);
    return NULL;
}

esp_err_t mdns_resolver_delete(mdns_resolver_t *resolver)
{
    bool found = false;
    esp_err_t err = ESP_OK;

    if (!resolver) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!mdns_priv_is_server_init()) {
        return ESP_ERR_INVALID_STATE;
    }

    mdns_priv_service_lock();
    mdns_resolver_state_t prev_state = resolver->state;
    for (mdns_resolver_t *it = s_resolver; it; it = it->next) {
        if (it->state != RESOLVER_OFF && it == resolver) {
            resolver->state = RESOLVER_OFF;
            found = true;
            break;
        }
    }

    if (!found) {
        mdns_priv_service_unlock();
        return ESP_ERR_NOT_FOUND;
    }

    err = send_resolver_action(ACTION_RESOLVER_END, resolver);
    if (err != ESP_OK) {
        resolver->state = prev_state;
    }

    mdns_priv_service_unlock();
    return err;
}

void mdns_srv_resolver_result_free(mdns_srv_resolver_result_t *result)
{
    if (!result) {
        return;
    }

    mdns_mem_free((char *)result->instance_name);
    mdns_mem_free((char *)result->service_type);
    mdns_mem_free((char *)result->proto);
    mdns_mem_free((char *)result->hostname);
    mdns_mem_free(result);
}
