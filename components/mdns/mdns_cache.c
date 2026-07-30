/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mdns_cache.h"

static const char *TAG = "mdns_cache";

static mdns_cache_entry_t *s_cache;
