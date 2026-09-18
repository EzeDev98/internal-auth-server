package com.internal.auth.feature.admin.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Body for the top-level "wipe everything" endpoint (Settings page danger
 * zone): SyncPoint, Notare, and internal-auth's own data together.
 *
 * @see com.internal.auth.feature.admin.web.TenantResetController
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class WipeAllRequest {

    /** Must equal the required confirmation phrase, or the request is rejected. */
    private String confirmation;

    /**
     * Forwarded to SyncPoint's own /admin/reset/wipe as includeSystemWallet.
     * Defaults to false (preserved) when the request body omits it - same
     * conservative default SyncPoint's own WipeRequest uses, since clearing
     * it can leave SyncPoint unable to fund/provision users until reseeded.
     */
    private Boolean includeSystemWallet;
}
