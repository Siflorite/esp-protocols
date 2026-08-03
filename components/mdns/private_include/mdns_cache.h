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

mdns_cache_entry_t *mdns_priv_cache_find_entry(const char *hostname, const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol);
mdns_service_cache_t *mdns_priv_cache_find_service(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *instance, const char *service, const char *proto, mdns_cache_entry_t **owner_entry);

mdns_cache_update_result_t mdns_priv_cache_update_ptr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *instance, const char *service, const char *proto, const char *subtype, uint32_t ttl);
mdns_cache_update_result_t mdns_priv_cache_update_srv(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *hostname, const char *instance, const char *service, const char *proto, uint16_t priority, uint16_t weight, uint16_t port, uint32_t ttl);
mdns_cache_update_result_t mdns_priv_cache_update_txt(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *instance, const char *service, const char *proto, mdns_txt_linked_item_t *txt, uint32_t ttl);
mdns_cache_update_result_t mdns_priv_cache_update_addr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *hostname, const esp_ip_addr_t *addr, uint32_t ttl);

void mdns_priv_cache_clear(void);

mdns_result_t *mdns_priv_cache_to_result(const mdns_browse_t *browse);
void mdns_priv_cache_verify_browse_result(const mdns_browse_t *browse);
#ifdef __cplusplus
}
#endif

#ifndef CONFIG_MDNS_CACHE_DEBUG
#define CONFIG_MDNS_CACHE_DEBUG 1
#endif
