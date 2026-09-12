package com.internal.auth.feature.admin.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/**
 * Result of a per-tenant wipe: pre-delete row counts per table, keyed the
 * same way SyncPoint's own DatabaseResetService.ResetResult is.
 *
 * @see com.internal.auth.feature.admin.web.TenantResetController
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TenantWipeResponse {
    private String appId;
    private Map<String, Long> deletedCounts;
}
