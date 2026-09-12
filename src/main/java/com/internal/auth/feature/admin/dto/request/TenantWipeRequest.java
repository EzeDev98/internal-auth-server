package com.internal.auth.feature.admin.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Body for the destructive per-tenant data wipe.
 *
 * @see com.internal.auth.feature.admin.web.TenantResetController
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TenantWipeRequest {

    /** The ClientApplication.clientId whose data is being wiped, e.g. "sync-point". */
    private String appId;

    /** Must equal the required confirmation phrase, or the request is rejected. */
    private String confirmation;
}
