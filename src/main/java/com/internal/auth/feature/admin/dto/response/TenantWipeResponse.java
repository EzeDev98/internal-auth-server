package com.internal.auth.feature.admin.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/** Result of a tenant wipe with deleted row counts per table. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TenantWipeResponse {
    private String appId;
    private Map<String, Long> deletedCounts;
}
