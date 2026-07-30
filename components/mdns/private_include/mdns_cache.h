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

/**
 * @brief Find a cache entry by hostname, esp_netif, and ip_protocol.
 *
 * @param hostname      The hostname to find.
 * @param esp_netif     Pointer to the esp_netif to find.
 * @param ip_protocol   IP protocol to find.
 *
 * @return Pointer to the cache entry if found, NULL otherwise.
 */
mdns_cache_entry_t *mdns_priv_cache_find_entry(const char *hostname, const esp_netif_t *esp_netif,
                                               mdns_ip_protocol_t ip_protocol);

/**
 * @brief Find a service cache entry by esp_netif, ip_protocol, instance, service, and proto.
 *
 * @param esp_netif     Pointer to the esp_netif to find.
 * @param ip_protocol   IP protocol to find.
 * @param instance      The instance name to find.
 * @param service       The service name to find.
 * @param proto         The protocol to find.
 * @param owner_entry   Receives the pointer to the cache entry that owns the service cache.
 *
 * @return Pointer to the service cache entry if found, NULL otherwise.
 */
mdns_service_cache_t *mdns_priv_cache_find_service(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol,
                                                   const char *instance, const char *service, const char *proto,
                                                   mdns_cache_entry_t **owner_entry);

/**
 * @brief Check if a host has a service by hostname, esp_netif, ip_protocol, service, and proto.
 *
 * @param hostname      The hostname to check.
 * @param esp_netif     Pointer to the esp_netif to check.
 * @param ip_protocol   IP protocol to check.
 * @param service       The service name to check.
 * @param proto         The protocol to check.
 *
 * @return true if the host has the service, false otherwise.
 */
bool mdns_priv_host_has_service(const char *hostname, const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol,
                                const char *service, const char *proto);

/**
 * @brief Remove all service caches by service and proto.
 *
 * @param service       The service name to remove.
 * @param proto         The protocol to remove.
 */
void mdns_priv_remove_service_caches(const char *service, const char *proto);

/**
 * @brief Remove a subtype from a service cache `_service._proto`.
 *
 * @param service       The service name to remove the subtype from.
 * @param proto         The protocol to remove the subtype from.
 * @param subtype       The subtype to remove.
 */
void mdns_priv_service_cache_remove_subtype(const char *service, const char *proto, const char *subtype);

/**
 * @brief Update a PTR record for service cache `_service._proto` with possible subtype.
 *
 * @param esp_netif     Pointer to the esp_netif.
 * @param ip_protocol   IP protocol.
 * @param instance      The instance name.
 * @param service       The service name.
 * @param proto         The protocol.
 * @param subtype       The subtype.
 * @param ttl           The PTR TTL.
 *
 * @return The result of the update, see @ref mdns_cache_update_result_t.
 *
 * @note The PTR record will be marked dirty when:
 *      - A new service is added to the cache.
 *      - A new subtype is appended to the service cache.
 *      - The PTR TTL is updated.
 *      - Receives a TTL=0 goodbye:
 *          - If @ref subtype is not null and the service cache has this subtype,
 *            the subtype will be removed from subtype list of this service cache.
 *          - If @ref subtype is null, the PTR record will be marked as absent.
 */
mdns_cache_update_result_t mdns_priv_cache_update_ptr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol,
                                                      const char *instance, const char *service, const char *proto,
                                                      const char *subtype, uint32_t ttl);

/**
 * @brief Update a SRV record for service cache `instance._service._proto`.
 *
 * @param esp_netif     Pointer to the esp_netif.
 * @param ip_protocol   IP protocol.
 * @param hostname      The hostname to update.
 * @param instance      The instance name.
 * @param service       The service name.
 * @param proto         The protocol.
 * @param priority      The priority to update.
 * @param weight        The weight to update.
 * @param port          The port to update.
 * @param ttl           The SRV TTL.
 *
 * @return The result of the update, see @ref mdns_cache_update_result_t.
 *
 * @note The SRV record will be marked dirty when:
 *      - A new SRV record is added to the service cache.
 *      - The service cache is moved to the host designated by @ref hostname.
 *      - The SRV record is updated.
 *      - Receives a TTL=0 goodbye: the SRV record will be marked as absent.
 */
mdns_cache_update_result_t mdns_priv_cache_update_srv(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol,
                                                      const char *hostname, const char *instance, const char *service,
                                                      const char *proto, uint16_t priority, uint16_t weight,
                                                      uint16_t port, uint32_t ttl);

/**
 * @brief Update a TXT record for service cache `instance._service._proto`.
 *
 * @param esp_netif     Pointer to the esp_netif.
 * @param ip_protocol   IP protocol.
 * @param instance      The instance name.
 * @param service       The service name.
 * @param proto         The protocol.
 * @param txt           The TXT record to update.
 * @param ttl           The TXT TTL.
 *
 * @return The result of the update, see @ref mdns_cache_update_result_t.
 *
 * @note The TXT record will be marked dirty when:
 *      - A new TXT record is added to the service cache.
 *      - The TXT record is updated.
 *      - Receives a TTL=0 goodbye: the TXT record will be marked as absent.
 */
mdns_cache_update_result_t mdns_priv_cache_update_txt(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol,
                                                      const char *instance, const char *service, const char *proto,
                                                      mdns_txt_linked_item_t *txt, uint32_t ttl);

/**
 * @brief Update an A/AAAA record for a cache entry `hostname`.
 *
 * @param esp_netif     Pointer to the esp_netif.
 * @param ip_protocol   IP protocol.
 * @param hostname      The hostname to update.
 * @param addr          The address to update.
 * @param ttl           The TTL.
 *
 * @return The result of the update, see @ref mdns_cache_update_result_t.
 *
 * @note When an A/AAAA record is updated (added, removed, or updated),
 *       all services under this cache entry will be marked dirty.
 */
mdns_cache_update_result_t mdns_priv_cache_update_addr(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol,
                                                       const char *hostname, const esp_ip_addr_t *addr, uint32_t ttl);

/**
 * @brief Clear all cache entries.
 */
void mdns_priv_cache_clear(void);

/**
 * @brief Convert a service cache to a mdns_result_t.
 *
 * @param entry       Pointer to the cache entry.
 * @param service     Pointer to the service cache.
 * @return The converted mdns_result_t.
 *
 * @note The ownership of the returned `mdns_result_t` is transferred to the caller.
 */
mdns_result_t *mdns_priv_service_cache_to_result(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service);

/**
 * @brief Process all dirty cache entries.
 *
 * @note This function is called by the MDNS task to process all dirty cache entries.
 *       It will generate temporary results, notify corresponding browsers, and clear the dirty flag.
 */
void mdns_priv_cache_process_dirty(void);

/**
 * @brief Replay all currently visible cache services to a newly registered browse.
 *
 * @return true if successfully notified, false otherwise
 */
bool mdns_priv_cache_notify_browse(mdns_browse_t *browse);
#ifdef __cplusplus
}
#endif
