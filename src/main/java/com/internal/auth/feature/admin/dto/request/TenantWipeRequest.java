package com.internal.auth.feature.admin.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for wiping one tenant's data. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TenantWipeRequest {
    private String appId;

    private String confirmation;
}
