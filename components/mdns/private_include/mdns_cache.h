/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stddef.h>
#include "mdns_private.h"

#ifdef __cplusplus
extern "C" {
#endif

mdns_cache_entry_t *mdns_priv_cache_find_entry(const char *hostname, const esp_netif_t *esp_netif);
mdns_service_cache_t *mdns_priv_cache_find_service(const esp_netif_t *esp_netif, const char *instance, const char *service, const char *proto);

mdns_cache_entry_t *mdns_priv_cache_add_entry(const char *hostname, const esp_netif_t *esp_netif);
mdns_service_cache_t *mdns_priv_cache_add_service(mdns_cache_entry_t *entry, const char *instance, const char *service, const char *proto);

esp_err_t mdns_priv_cache_update_ptr(mdns_service_cache_t *cache, const char *instance, const char *service, const char *proto);
#ifdef __cplusplus
}
#endif
