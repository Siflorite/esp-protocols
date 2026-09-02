/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "esp_netif_ip_addr.h"
#include "esp_netif_types.h"
#include "mdns.h"
#include "mdns_cache.h"
#include "mdns_mem_caps.h"
#include "mdns_mem_caps_test.h"
#include "mdns_private.h"
#include "mock_mdns_browser.h"
#include "unity.h"
#include "unity_internals.h"

#define INSTANCE    "_instance"
#define INSTANCE2   "_instance-2"
#define SERVICE     "_http"
#define SERVICE2    "_ftp"
#define PROTO       "_tcp"
#define PROTO2      "_udp"
#define HOSTNAME    "device"

#define PTR_TTL        120
#define SRV_TTL        130
#define TXT_TTL        140
#define ADDR_TTL       150

#define SRV_PRIORITY   10
#define SRV_WEIGHT     20
#define SRV_PORT       8080

typedef struct {
    size_t update_calls;
    size_t goodbye_calls;

    bool update_result;
    bool goodbye_result;

    mdns_cache_record_mask_t records;
    mdns_ip_protocol_t ip_protocol;
    const esp_netif_t *esp_netif;

    bool ptr_present;
    bool srv_present;
    bool txt_present;

    uint32_t ptr_ttl;
    uint32_t srv_ttl;
    uint32_t txt_ttl;

    uint16_t priority;
    uint16_t weight;
    uint16_t port;

    size_t address_count;
    size_t txt_count;

    // These pointers are references to the pointers in service cache item during tests,
    // and should only be used after TXT/ADDR cache has been updated and before service cache is cleaned!
    // Do not manually free them, they should be maintained by mdns_cache.
    const mdns_txt_linked_item_t *txt;
    const mdns_cache_addr_t *addr;

    char hostname[MDNS_NAME_BUF_LEN];
    char instance[MDNS_NAME_BUF_LEN];
    char service[MDNS_NAME_BUF_LEN];
    char proto[MDNS_NAME_BUF_LEN];
} cache_observer_t;

static cache_observer_t s_observer;
// Provide mock `esp_netif_t` pointers
static uint8_t s_netif_storage_a;
static uint8_t s_netif_storage_b;

// ----------------- Helper functions -----------------

static esp_netif_t *test_netif_a(void)
{
    return (esp_netif_t *)&s_netif_storage_a;
}

static esp_netif_t *test_netif_b(void)
{
    return (esp_netif_t *)&s_netif_storage_b;
}

static void reset_observer(void)
{
    memset(&s_observer, 0, sizeof(s_observer));
    s_observer.update_result = true;
    s_observer.goodbye_result = true;
}

static void copy_optional_string(char *dst, size_t dst_size, const char *src)
{
    if (!src) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static size_t count_addresses(const mdns_cache_addr_t *addr)
{
    size_t count = 0;

    while (addr) {
        count++;
        addr = addr->next;
    }

    return count;
}

static size_t count_txt(const mdns_txt_linked_item_t *txt)
{
    size_t count = 0;

    while (txt) {
        count++;
        txt = txt->next;
    }

    return count;
}

static void capture_cache(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                          mdns_cache_record_mask_t records)
{
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_NOT_NULL(service);
    s_observer.records = records;
    s_observer.ip_protocol = entry->ip_protocol;
    s_observer.esp_netif = entry->esp_netif;

    s_observer.ptr_present = service->ptr_present;
    s_observer.srv_present = service->srv_present;
    s_observer.txt_present = service->txt_present;

    s_observer.ptr_ttl = service->ptr_ttl;
    s_observer.srv_ttl = service->srv_ttl;
    s_observer.txt_ttl = service->txt_ttl;

    s_observer.priority = service->priority;
    s_observer.weight = service->weight;
    s_observer.port = service->port;

    s_observer.address_count = count_addresses(entry->addr_list);
    s_observer.txt_count = count_txt(service->txt_list);

    s_observer.txt = service->txt_list;
    s_observer.addr = entry->addr_list;

    copy_optional_string(s_observer.hostname, sizeof(s_observer.hostname), entry->hostname);
    copy_optional_string(s_observer.instance, sizeof(s_observer.instance), service->instance_name);
    copy_optional_string(s_observer.service, sizeof(s_observer.service), service->service);
    copy_optional_string(s_observer.proto, sizeof(s_observer.proto), service->proto);
}

static bool browse_update_callback(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                   mdns_cache_record_mask_t records, int cmock_num_calls)
{
    (void)cmock_num_calls;
    s_observer.update_calls++;
    capture_cache(entry, service, records);
    return s_observer.update_result;
}

static bool browse_goodbye_callback(const mdns_cache_entry_t *entry, const mdns_service_cache_t *service,
                                    int cmock_num_calls)
{
    (void)cmock_num_calls;
    s_observer.goodbye_calls++;
    capture_cache(entry, service, 0);
    return s_observer.goodbye_result;
}

static mdns_txt_linked_item_t *clone_txt(const mdns_txt_linked_item_t *src_txt)
{
    mdns_txt_linked_item_t *item = mdns_mem_calloc(1, sizeof(mdns_txt_linked_item_t));
    TEST_ASSERT_NOT_NULL(item);

    item->key = mdns_mem_strdup(src_txt->key);
    TEST_ASSERT_NOT_NULL(item->key);

    item->value_len = src_txt->value_len;

    if (src_txt->value_len > 0) {
        item->value = mdns_mem_malloc(src_txt->value_len);
        TEST_ASSERT_NOT_NULL(item->value);
        memcpy(item->value, src_txt->value, src_txt->value_len);
    }

    return item;
}

static bool find_txt_in_txt_list(const mdns_txt_linked_item_t *txt_list, const mdns_txt_linked_item_t *target)
{
    if (!txt_list || !target) {
        return false;
    }

    for (const mdns_txt_linked_item_t *it = txt_list; it; it = it->next) {
        if (strcasecmp(it->key, target->key) == 0) {
            if (it->value_len != target->value_len) {
                return false; // Do not allow duplicated keys
            }
            return it->value_len == 0 || memcmp(it->value, target->value, it->value_len) == 0;
        }
    }

    return false;
}

static esp_ip_addr_t make_ipv4(uint32_t address)
{
    esp_ip_addr_t addr = {0};

    addr.type = ESP_IPADDR_TYPE_V4;
    addr.u_addr.ip4.addr = address;
    return addr;
}
static esp_ip_addr_t make_ipv6(const uint32_t address[4])
{
    esp_ip_addr_t addr = {0};

    addr.type = ESP_IPADDR_TYPE_V6;
    for (int i = 0; i < 4; i++) {
        addr.u_addr.ip6.addr[i] = address[i];
    }
    return addr;
}

static void assert_memory(size_t baseline)
{
    TEST_ASSERT_EQUAL_size_t(baseline, mdns_mem_get_allocation_counts());
}

static void add_service_cache(const esp_netif_t *esp_netif, mdns_ip_protocol_t ip_protocol, const char *hostname,
                              const char *instance, const char *service, const char *proto)
{
    TEST_ASSERT_EQUAL(MDNS_CACHE_ADDED, mdns_priv_cache_update_ptr(esp_netif, ip_protocol, instance, service, proto, PTR_TTL));
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_srv(esp_netif, ip_protocol, hostname, instance, service, proto, 0, 0, SRV_PORT, SRV_TTL));
}

static mdns_cache_update_result_t update_test_record(mdns_cache_record_type_t record_type, bool goodbye)
{
    static const mdns_txt_linked_item_t txt = {
        .key = "key",
        .value = "value",
        .value_len = 5,
        .next = NULL,
    };
    const esp_ip_addr_t addr = make_ipv4(0x0101A8C0);

    switch (record_type) {
    case MDNS_CACHE_RECORD_PTR:
        return mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                          INSTANCE, SERVICE, PROTO, goodbye ? 0 : PTR_TTL);
    case MDNS_CACHE_RECORD_SRV:
        return mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                          SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, goodbye ? 0 : SRV_TTL);
    case MDNS_CACHE_RECORD_TXT:
        return mdns_priv_cache_update_txt(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE,
                                          SERVICE, PROTO, clone_txt(&txt), goodbye ? 0 : TXT_TTL);
    case MDNS_CACHE_RECORD_ADDR:
        return mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME,
                                           &addr, goodbye ? 0 : ADDR_TTL);
    default:
        TEST_FAIL_MESSAGE("Invalid record type");
        return MDNS_CACHE_ERROR;
    }
}

static void insert_complete_service(void)
{
    TEST_ASSERT_EQUAL(MDNS_CACHE_ADDED, update_test_record(MDNS_CACHE_RECORD_PTR, false));
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, update_test_record(MDNS_CACHE_RECORD_SRV, false));
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, update_test_record(MDNS_CACHE_RECORD_TXT, false));
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, update_test_record(MDNS_CACHE_RECORD_ADDR, false));
}

static void assert_observed_complete_service(void)
{
    TEST_ASSERT_EQUAL_PTR(test_netif_a(), s_observer.esp_netif);
    TEST_ASSERT_EQUAL(MDNS_IP_PROTOCOL_V4, s_observer.ip_protocol);

    TEST_ASSERT_TRUE(s_observer.ptr_present);
    TEST_ASSERT_TRUE(s_observer.srv_present);
    TEST_ASSERT_TRUE(s_observer.txt_present);

    TEST_ASSERT_EQUAL_UINT32(PTR_TTL, s_observer.ptr_ttl);
    TEST_ASSERT_EQUAL_UINT32(SRV_TTL, s_observer.srv_ttl);
    TEST_ASSERT_EQUAL_UINT32(TXT_TTL, s_observer.txt_ttl);

    TEST_ASSERT_EQUAL_UINT16(SRV_PRIORITY, s_observer.priority);
    TEST_ASSERT_EQUAL_UINT16(SRV_WEIGHT, s_observer.weight);
    TEST_ASSERT_EQUAL_UINT16(SRV_PORT, s_observer.port);

    TEST_ASSERT_EQUAL_size_t(1, s_observer.txt_count);
    TEST_ASSERT_EQUAL_size_t(1, s_observer.address_count);

    TEST_ASSERT_EQUAL_STRING(HOSTNAME, s_observer.hostname);
    TEST_ASSERT_EQUAL_STRING(INSTANCE, s_observer.instance);
    TEST_ASSERT_EQUAL_STRING(SERVICE, s_observer.service);
    TEST_ASSERT_EQUAL_STRING(PROTO, s_observer.proto);
}

static void swap(mdns_cache_record_type_t *a, mdns_cache_record_type_t *b)
{
    mdns_cache_record_type_t temp = *a;
    *a = *b;
    *b = temp;
}

static bool next_permutation(mdns_cache_record_type_t *arr, size_t n)
{
    if (n < 2) {
        return false;
    }

    size_t i = n - 1;
    while (i > 0 && arr[i - 1] >= arr[i]) {
        i--;
    }
    if (i == 0) {
        return false;
    }
    i--;

    size_t j = n - 1;
    while (arr[j] <= arr[i]) {
        --j;
    }

    swap(&arr[i], &arr[j]);

    for (size_t l = i + 1, r = n - 1; l < r; ++l, --r) {
        swap(&arr[l], &arr[r]);
    }

    return true;
}

// ----------------- Test functions -----------------

void mdns_test_set_up(void)
{
    mdns_priv_cache_clear();
    reset_observer();
}

void mdns_test_tear_down(void)
{
    mdns_priv_cache_clear();
}

void setup_cmock(void)
{
    mdns_priv_browse_update_from_service_cache_Stub(browse_update_callback);
    mdns_priv_browse_notify_ptr_goodbye_from_service_cache_Stub(browse_goodbye_callback);

    mdns_priv_browse_notify_from_service_cache_IgnoreAndReturn(true);
    mdns_priv_browse_has_service_IgnoreAndReturn(false);
}

static void test_cache_ptr_add_repeat_update_remove(void)
{
    size_t baseline = mdns_mem_get_allocation_counts();

    // Scenario 1: Add new PTR record
    TEST_ASSERT_EQUAL(MDNS_CACHE_ADDED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                   INSTANCE, SERVICE, PROTO, PTR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT8(MDNS_CACHE_RECORD_PTR, s_observer.records);
    TEST_ASSERT_TRUE(s_observer.ptr_present);
    TEST_ASSERT_EQUAL_UINT32(PTR_TTL, s_observer.ptr_ttl);
    TEST_ASSERT_EQUAL_STRING(INSTANCE, s_observer.instance);
    TEST_ASSERT_EQUAL_STRING(SERVICE, s_observer.service);
    TEST_ASSERT_EQUAL_STRING(PROTO, s_observer.proto);

    // Scenario 2: Update the same service cache with identical PTR TTL
    TEST_ASSERT_EQUAL(MDNS_CACHE_NO_CHANGE, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                       INSTANCE, SERVICE, PROTO, PTR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);

    // Scenario 3: Update the same service cache with different PTR TTL
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                     INSTANCE, SERVICE, PROTO, 240));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(2, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT32(240, s_observer.ptr_ttl);

    // Scenario 4: Remove cache with PTR TTL=0
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                     INSTANCE, SERVICE, PROTO, 0));
    TEST_ASSERT_EQUAL_size_t(1, s_observer.goodbye_calls);
    assert_memory(baseline);
}

static void test_cache_srv_add_repeat_update_remove(void)
{
    size_t baseline = mdns_mem_get_allocation_counts();

    // Scenario 1: Add new SRV record
    TEST_ASSERT_EQUAL(MDNS_CACHE_ADDED, mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                                                   SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, SRV_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT8(MDNS_CACHE_RECORD_SRV, s_observer.records);
    TEST_ASSERT_TRUE(s_observer.srv_present);
    TEST_ASSERT_EQUAL_UINT32(SRV_TTL, s_observer.srv_ttl);
    TEST_ASSERT_EQUAL_STRING(HOSTNAME, s_observer.hostname);
    TEST_ASSERT_EQUAL_STRING(INSTANCE, s_observer.instance);
    TEST_ASSERT_EQUAL_STRING(SERVICE, s_observer.service);
    TEST_ASSERT_EQUAL_STRING(PROTO, s_observer.proto);
    TEST_ASSERT_EQUAL_UINT16(SRV_PRIORITY, s_observer.priority);
    TEST_ASSERT_EQUAL_UINT16(SRV_WEIGHT, s_observer.weight);
    TEST_ASSERT_EQUAL_UINT16(SRV_PORT, s_observer.port);

    // Scenario 2: Update the same service cache with identical priority, weight, port, and SRV TTL
    TEST_ASSERT_EQUAL(MDNS_CACHE_NO_CHANGE, mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                                                       SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, SRV_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);

    // Scenario 3: Update the same service cache with different SRV record
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                                                     SERVICE, PROTO, 30, 40, 8081, 240));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(2, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT32(240, s_observer.srv_ttl);
    TEST_ASSERT_EQUAL_UINT16(30, s_observer.priority);
    TEST_ASSERT_EQUAL_UINT16(40, s_observer.weight);
    TEST_ASSERT_EQUAL_UINT16(8081, s_observer.port);

    // Scenario 4: Remove cache with SRV TTL=0
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                                                     SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, 0));
    assert_memory(baseline);
}

static void test_cache_txt_add_repeat_update_remove(void)
{
    static const uint8_t binary_arr[] = {0, 0, 0, 0, 255};
    // Normal TXT item
    static const mdns_txt_linked_item_t txt_1 = {
        .key = "key1",
        .value = "value",
        .value_len = 5,
        .next = NULL,
    };
    // Simulate TXT item with no value
    static const mdns_txt_linked_item_t txt_2 = {
        .key = "key2",
        .value = NULL,
        .value_len = 0,
        .next = NULL,
    };
    // Simulate TXT item with binary value
    static const mdns_txt_linked_item_t txt_3 = {
        .key = "key2",
        .value = (char *)binary_arr,
        .value_len = sizeof(binary_arr),
        .next = NULL,
    };

    size_t baseline = mdns_mem_get_allocation_counts();

    // Scenario 1: Add new TXT record
    mdns_txt_linked_item_t *test1_txt1 = clone_txt(&txt_1);
    TEST_ASSERT_EQUAL(MDNS_CACHE_ADDED, mdns_priv_cache_update_txt(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE,
                                                                   SERVICE, PROTO, test1_txt1, TXT_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT8(MDNS_CACHE_RECORD_TXT, s_observer.records);
    TEST_ASSERT_TRUE(s_observer.txt_present);
    TEST_ASSERT_EQUAL_UINT32(TXT_TTL, s_observer.txt_ttl);
    TEST_ASSERT_EQUAL_STRING(INSTANCE, s_observer.instance);
    TEST_ASSERT_EQUAL_STRING(SERVICE, s_observer.service);
    TEST_ASSERT_EQUAL_STRING(PROTO, s_observer.proto);
    TEST_ASSERT_EQUAL_size_t(1, s_observer.txt_count);

    // Scenario 2: Update the same service cache with identical TXT item and TTL
    mdns_txt_linked_item_t *test2_txt1 = clone_txt(&txt_1);
    TEST_ASSERT_EQUAL(MDNS_CACHE_NO_CHANGE, mdns_priv_cache_update_txt(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE,
                                                                       SERVICE, PROTO, test2_txt1, TXT_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);

    // Scenario 3: Update the same service cache with different TXT item and TTL
    mdns_txt_linked_item_t *test3_txt1 = clone_txt(&txt_1);
    mdns_txt_linked_item_t *test3_txt2 = clone_txt(&txt_2);
    test3_txt1->next = test3_txt2;
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_txt(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE,
                                                                     SERVICE, PROTO, test3_txt1, 240));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(2, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT32(240, s_observer.txt_ttl);
    TEST_ASSERT_EQUAL_size_t(2, s_observer.txt_count);

    // Scenario 4: Update the same service cache with a TXT item different in value
    mdns_txt_linked_item_t *test4_txt1 = clone_txt(&txt_1);
    mdns_txt_linked_item_t *test4_txt3 = clone_txt(&txt_3);
    test4_txt1->next = test4_txt3;
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_txt(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE,
                                                                     SERVICE, PROTO, test4_txt1, 240));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(3, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(2, s_observer.txt_count);
    TEST_ASSERT_TRUE(find_txt_in_txt_list(s_observer.txt, &txt_3));

    // Scenario 5: Remove cache with TXT TTL=0
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_txt(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE,
                                                                     SERVICE, PROTO, NULL, 0));
    assert_memory(baseline);
}

static void test_cache_addr_add_repeat_update_remove(void)
{
    static const uint32_t ip6_addr[4] = {0x20010db8, 0, 0, 0x00000001};
    static const uint32_t ip4_addr_1 = 0x0101A8C0;
    static const uint32_t ip4_addr_2 = 0x0201A8C0;

    const esp_ip_addr_t addr_1 = make_ipv4(ip4_addr_1);
    const esp_ip_addr_t addr_2 = make_ipv4(ip4_addr_2);
    const esp_ip_addr_t addr_3 = make_ipv6(ip6_addr);

    // Because currently `mdns_priv_cache_process_sync()` only notifies browses, we need to setup an SRV record to establish a service cache.
    // So that `browse_update_callback()` stub can update `s_observer`.
    (void)mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME, INSTANCE,
                                     SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, SRV_TTL);
    size_t baseline = mdns_mem_get_allocation_counts();

    // Scenario 1: Add new A record
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_1, ADDR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT8(MDNS_CACHE_RECORD_ADDR | MDNS_CACHE_RECORD_SRV, s_observer.records);
    TEST_ASSERT_NOT_NULL(s_observer.addr);
    TEST_ASSERT_EQUAL_UINT32(ADDR_TTL, s_observer.addr->ttl);
    TEST_ASSERT_EQUAL_UINT32(ip4_addr_1, s_observer.addr->addr.u_addr.ip4.addr);
    TEST_ASSERT_EQUAL_STRING(HOSTNAME, s_observer.hostname);
    TEST_ASSERT_EQUAL_size_t(1, s_observer.address_count);

    // Scenario 2: Update the same service cache with identical A record
    TEST_ASSERT_EQUAL(MDNS_CACHE_NO_CHANGE, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                        &addr_1, ADDR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);

    // Scenario 3: Update the A record with new TTL
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_1, 240));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(2, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT32(240, s_observer.addr->ttl);
    TEST_ASSERT_EQUAL_size_t(1, s_observer.address_count);

    // Scenario 4: Add new A record
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_2, ADDR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(3, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(2, s_observer.address_count);

    // Scenario 5: Add new AAAA record
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_3, ADDR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(4, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(3, s_observer.address_count);

    // Scenario 6: Remove all addresses with TTL=0
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_1, 0));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(5, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(2, s_observer.address_count);
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_2, 0));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(6, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(1, s_observer.address_count);
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME,
                                                                      &addr_3, 0));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(7, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(0, s_observer.address_count);
    assert_memory(baseline);

    // Scenario 7: `mdns_priv_cache_update_existing_addr()` cannot create new entry
    size_t baseline_s7 = mdns_mem_get_allocation_counts();
    TEST_ASSERT_EQUAL(MDNS_CACHE_NO_CHANGE, mdns_priv_cache_update_existing_addr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                                 HOSTNAME, &addr_1, ADDR_TTL));
    assert_memory(baseline_s7);

    (void)mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                     SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, SRV_TTL);
    baseline_s7 = mdns_mem_get_allocation_counts();

    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_addr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                      HOSTNAME, &addr_1, ADDR_TTL));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(8, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT32(ADDR_TTL, s_observer.addr->ttl);
    TEST_ASSERT_EQUAL(MDNS_CACHE_UPDATED, mdns_priv_cache_update_existing_addr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                               HOSTNAME, &addr_1, 240));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(9, s_observer.update_calls);
    TEST_ASSERT_EQUAL_UINT32(240, s_observer.addr->ttl);
    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_existing_addr(test_netif_a(), MDNS_IP_PROTOCOL_V4,
                                                                               HOSTNAME, &addr_1, 0));
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(10, s_observer.update_calls);
    TEST_ASSERT_EQUAL_size_t(0, s_observer.address_count);

    assert_memory(baseline_s7);
    (void)mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE,
                                     SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, 0);
    (void)mdns_priv_cache_update_srv(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME, INSTANCE,
                                     SERVICE, PROTO, SRV_PRIORITY, SRV_WEIGHT, SRV_PORT, 0);
}

static void test_cache_permute_full_service(void)
{
    // Must sort in ascending order
    mdns_cache_record_type_t record_types[] = {
        MDNS_CACHE_RECORD_PTR,
        MDNS_CACHE_RECORD_SRV,
        MDNS_CACHE_RECORD_TXT,
        MDNS_CACHE_RECORD_ADDR
    };

    const size_t n = sizeof(record_types) / sizeof(mdns_cache_record_type_t);
    size_t permutation_count = 0;
    size_t factorial = 1;
    for (size_t i = 1; i <= n; i++) {
        factorial *= i;
    }

    do {
        mdns_priv_cache_clear();
        reset_observer();
        size_t baseline = mdns_mem_get_allocation_counts();

        for (size_t i = 0; i < n; i++) {
            mdns_cache_update_result_t result = update_test_record(record_types[i], false);
            TEST_ASSERT_NOT_EQUAL(MDNS_CACHE_NO_CHANGE, result);
            TEST_ASSERT_NOT_EQUAL(MDNS_CACHE_ERROR, result);
        }

        TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));

        mdns_priv_cache_process_sync();
        // If ADDR record comes before SRV, it will create a cache entry first with no service cache.
        // Thus we cannot get ADDR record flag of the service cache, but we can check the address pointer.
        TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
        TEST_ASSERT_TRUE((s_observer.records & MDNS_CACHE_RECORD_PTR) != 0);
        TEST_ASSERT_TRUE((s_observer.records & MDNS_CACHE_RECORD_SRV) != 0);
        TEST_ASSERT_TRUE((s_observer.records & MDNS_CACHE_RECORD_TXT) != 0);
        TEST_ASSERT_NOT_NULL(s_observer.addr);
        assert_observed_complete_service();

        // PTR TTL=0 removes the whole service cache
        TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, update_test_record(MDNS_CACHE_RECORD_PTR, true));
        TEST_ASSERT_EQUAL_size_t(1, s_observer.goodbye_calls);
        TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
        assert_memory(baseline);
        permutation_count++;
    } while (next_permutation(record_types, n));

    TEST_ASSERT_EQUAL_size_t(factorial, permutation_count);
}

static void test_cache_complete_service_record_goodbyes(void)
{
    mdns_cache_record_type_t goodbye_record_types[] = {
        MDNS_CACHE_RECORD_SRV,
        MDNS_CACHE_RECORD_TXT,
        MDNS_CACHE_RECORD_ADDR
    };

    // Test single record removal
    for (size_t i = 0; i < sizeof(goodbye_record_types) / sizeof(mdns_cache_record_type_t); i++) {
        mdns_priv_cache_clear();
        reset_observer();
        size_t baseline = mdns_mem_get_allocation_counts();

        insert_complete_service();
        // `mdns_priv_browse_update_from_service_cache()` is only called once on sync
        // And sync records are cleared.
        mdns_priv_cache_process_sync();
        TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
        assert_observed_complete_service();
        mdns_priv_cache_process_sync();
        TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);

        // Cache updated while service cache not removed
        reset_observer();
        mdns_cache_update_result_t expected_result = goodbye_record_types[i] == MDNS_CACHE_RECORD_ADDR ? MDNS_CACHE_REMOVED : MDNS_CACHE_UPDATED;
        TEST_ASSERT_EQUAL(expected_result, update_test_record(goodbye_record_types[i], true));
        TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));

        // Updated record is marked to sync
        mdns_priv_cache_process_sync();
        TEST_ASSERT_EQUAL_size_t(1, s_observer.update_calls);
        TEST_ASSERT_EQUAL_UINT8(goodbye_record_types[i], s_observer.records);

        // Other records exist and unchanged, but deleted record no longer exists
        TEST_ASSERT_TRUE(s_observer.ptr_present);
        switch (goodbye_record_types[i]) {
        case MDNS_CACHE_RECORD_SRV:
            TEST_ASSERT_FALSE(s_observer.srv_present);
            TEST_ASSERT_TRUE(s_observer.txt_present);
            TEST_ASSERT_NOT_NULL(s_observer.addr);
            TEST_ASSERT_EQUAL_UINT32(0, s_observer.srv_ttl);
            break;
        case MDNS_CACHE_RECORD_TXT:
            TEST_ASSERT_TRUE(s_observer.srv_present);
            TEST_ASSERT_FALSE(s_observer.txt_present);
            TEST_ASSERT_NOT_NULL(s_observer.addr);
            TEST_ASSERT_EQUAL_UINT32(0, s_observer.txt_ttl);
            break;
        case MDNS_CACHE_RECORD_ADDR:
            TEST_ASSERT_TRUE(s_observer.srv_present);
            TEST_ASSERT_TRUE(s_observer.txt_present);
            TEST_ASSERT_NULL(s_observer.addr);
            TEST_ASSERT_EQUAL_size_t(0, s_observer.address_count);
            break;
        default:
            TEST_FAIL_MESSAGE("Unallowed test goodbye record");
        }

        // Cleanup
        TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, update_test_record(MDNS_CACHE_RECORD_PTR, true));
        TEST_ASSERT_EQUAL_size_t(1, s_observer.goodbye_calls);
        TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
        assert_memory(baseline);
    }
}

static void test_cache_isolation(void)
{
    // Service caches should be isolated by service type, esp_netif and ip protocol
    size_t baseline = mdns_mem_get_allocation_counts();

    add_service_cache(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE, SERVICE, PROTO);
    add_service_cache(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE, SERVICE2, PROTO2);
    add_service_cache(test_netif_b(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE, SERVICE, PROTO);
    add_service_cache(test_netif_a(), MDNS_IP_PROTOCOL_V6, HOSTNAME, INSTANCE, SERVICE, PROTO);
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE2, PROTO2));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_b(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V6, SERVICE, PROTO));

    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE, SERVICE, PROTO, 0));
    TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE2, PROTO2));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_b(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V6, SERVICE, PROTO));

    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE, SERVICE2, PROTO2, 0));
    TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE2, PROTO2));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_b(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V6, SERVICE, PROTO));

    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_b(), MDNS_IP_PROTOCOL_V4, INSTANCE, SERVICE, PROTO, 0));
    TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_b(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V6, SERVICE, PROTO));

    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V6, INSTANCE, SERVICE, PROTO, 0));
    TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V6, SERVICE, PROTO));
    assert_memory(baseline);

    // Two instances
    mdns_priv_cache_clear();
    reset_observer();
    baseline = mdns_mem_get_allocation_counts();

    add_service_cache(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE, SERVICE, PROTO);
    add_service_cache(test_netif_a(), MDNS_IP_PROTOCOL_V4, HOSTNAME, INSTANCE2, SERVICE, PROTO);
    mdns_priv_cache_process_sync();
    TEST_ASSERT_EQUAL_size_t(2, s_observer.update_calls);

    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE, SERVICE, PROTO, 0));
    TEST_ASSERT_TRUE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_EQUAL_size_t(1, s_observer.goodbye_calls);

    TEST_ASSERT_EQUAL(MDNS_CACHE_REMOVED, mdns_priv_cache_update_ptr(test_netif_a(), MDNS_IP_PROTOCOL_V4, INSTANCE2, SERVICE, PROTO, 0));
    TEST_ASSERT_FALSE(mdns_priv_cache_host_has_service(HOSTNAME, test_netif_a(), MDNS_IP_PROTOCOL_V4, SERVICE, PROTO));
    TEST_ASSERT_EQUAL_size_t(2, s_observer.goodbye_calls);
    assert_memory(baseline);
}

void run_unity_tests(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cache_ptr_add_repeat_update_remove);
    RUN_TEST(test_cache_srv_add_repeat_update_remove);
    RUN_TEST(test_cache_txt_add_repeat_update_remove);
    RUN_TEST(test_cache_addr_add_repeat_update_remove);
    RUN_TEST(test_cache_permute_full_service);
    RUN_TEST(test_cache_complete_service_record_goodbyes);
    RUN_TEST(test_cache_isolation);
    UNITY_END();
}
