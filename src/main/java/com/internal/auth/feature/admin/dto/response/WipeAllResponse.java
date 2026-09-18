package com.internal.auth.feature.admin.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * Result of the top-level "wipe everything" endpoint. Steps run in a fixed
 * order (sync-point, notare, notare-internal-auth-tenant) and stop at the
 * first failure - see WipeAllService's class Javadoc for why partial
 * completion is reported rather than retried or rolled back.
 * `completedFully` is true only if every step in `steps` succeeded; the
 * first entry with success=false is where it stopped, and any step after
 * that point was never attempted (simply absent from the list).
 *
 * @see com.internal.auth.feature.admin.web.TenantResetController
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class WipeAllResponse {

    private boolean completedFully;
    private List<Step> steps;

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Step {
        /** "sync-point", "notare", or "notare-internal-auth-tenant". */
        private String service;
        private boolean success;
        private String message;
        /** Whatever detail is available: deleted-row counts, or null. */
        private Map<String, Long> deletedCounts;
    }
}
