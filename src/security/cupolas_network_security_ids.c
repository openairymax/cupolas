// SPDX-FileCopyrightText: 2025-2026 SPHARX Ltd.
// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0

/*
 *
 * cupolas_network_security_ids.c - Network Security: Intrusion Detection Implementation
 */

/**
 * @file cupolas_network_security_ids.c
 * @brief Network security: detection engine domain.
 *
 * Implements the IDS switch, connection anomaly detection, and alert
 * callback registration.
 */

#include "cupolas_network_security_internal.h"

int cupolas_net_ids_enable(bool enabled)
{
    g_net_security.manager.enable_ids = enabled;
    return 0;
}

int cupolas_net_detect_anomaly(const cupolas_connection_info_t *connection)
{
    if (!connection)
        return 0;

    int anomaly_detected = 0;
    const char *alert_type = NULL;
    const char *details = NULL;

    if (connection->bytes_sent > 100 * 1024 * 1024) {
        anomaly_detected = 1;
        alert_type = "HIGH_BANDWIDTH";
        details = "Unusually high bandwidth usage detected";
    }

    if (!connection->is_encrypted && g_net_security.manager.http.enforce_https) {
        anomaly_detected = 1;
        alert_type = "UNENCRYPTED_CONNECTION";
        details = "Unencrypted connection detected";
    }

    if (anomaly_detected && g_net_security.ids_callback) {
        g_net_security.ids_callback(alert_type, details, connection);
    }

    return anomaly_detected;
}

int cupolas_net_ids_set_callback(void (*callback)(const char *alert_type, const char *details,
                                                  const cupolas_connection_info_t *conn))
{
    g_net_security.ids_callback = callback;
    return 0;
}
