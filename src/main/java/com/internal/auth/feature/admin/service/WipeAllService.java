package com.internal.auth.feature.admin.service;

import com.internal.auth.feature.admin.client.DownstreamAppWipeClient;
import com.internal.auth.feature.admin.client.DownstreamWipeException;
import com.internal.auth.feature.admin.dto.response.WipeAllResponse;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Orchestrates the Settings-page "wipe everything" danger-zone button:
 * internal-auth is meant to be the final authority for the whole WM test
 * environment, so this is the one place that reaches out and wipes
 * SyncPoint and Notare together with internal-auth's own data, rather than
 * relying on each app's own admin panel to be triggered separately.
 * <p>
 * This does NOT change how SyncPoint's own {@code /admin/reset/wipe}
 * works - it stays exactly as-is, callable on its own, wiping only
 * SyncPoint + its own internal-auth tenant data. This class only adds a
 * second caller for it.
 * <p>
 * <h2>Notare is not (yet) an internal-auth tenant</h2>
 * Unlike SyncPoint, Notare has no integration with internal-auth-server
 * today - it runs its own fully local user/auth system, with no
 * clientApplicationId, no InternalAuthClient-equivalent, nothing. The
 * third step below still checks for a ClientApplication registered under
 * {@code notare.internal-auth-client-id} so this stays correct
 * automatically if Notare is ever migrated onto internal-auth without
 * needing to revisit this class - today that check will simply find
 * nothing and report the step as skipped.
 * <p>
 * <h2>Stop-on-first-failure</h2>
 * Each step is a separate, non-transactional remote operation (SyncPoint's
 * own database, Notare's own database, and internal-auth's own tables are
 * three different systems - there is no distributed transaction spanning
 * them). If one step fails, later steps are not attempted: continuing
 * regardless would risk ending up with, say, SyncPoint and Notare wiped
 * but internal-auth's own identity data still present with no way to tell
 * from the response alone that anything was left over. Stopping means the
 * returned report always reflects reality - everything listed as
 * successful really is gone, and the first failure marks exactly where an
 * operator needs to look before retrying.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WipeAllService {

    private final DownstreamAppWipeClient downstreamAppWipeClient;
    private final TenantDataWipeService tenantDataWipeService;
    private final ClientApplicationRepository clientApplicationRepository;

    @Value("${notare.internal-auth-client-id:notare}")
    private String notareClientId;

    public WipeAllResponse wipeEverything(boolean includeSystemWallet) {
        List<WipeAllResponse.Step> steps = new ArrayList<>();

        boolean syncPointOk = attemptStep(steps, "sync-point", () -> {
            Map<String, Object> result = downstreamAppWipeClient.wipeSyncPoint(includeSystemWallet);
            return toLongMap(result);
        });
        if (!syncPointOk) {
            return new WipeAllResponse(false, steps);
        }

        boolean notareOk = attemptStep(steps, "notare", () -> {
            downstreamAppWipeClient.wipeNotare();
            return null;
        });
        if (!notareOk) {
            return new WipeAllResponse(false, steps);
        }

        Optional<ClientApplication> notareClient = clientApplicationRepository.findByClientId(notareClientId);
        if (notareClient.isEmpty()) {
            steps.add(new WipeAllResponse.Step("notare-internal-auth-tenant", true,
                    "Skipped - no ClientApplication registered for clientId=" + notareClientId
                            + " (Notare does not integrate with internal-auth yet).",
                    null));
            return new WipeAllResponse(true, steps);
        }

        boolean notareTenantOk = attemptStep(steps, "notare-internal-auth-tenant",
                () -> tenantDataWipeService.wipeTenant(notareClientId));
        if (!notareTenantOk) {
            return new WipeAllResponse(false, steps);
        }

        boolean ahorraOk = attemptStep(steps, "ahorra", () -> {
            Map<String, Object> result = downstreamAppWipeClient.wipeAhorra();
            return toLongMap(result);
        });
        if (!ahorraOk) {
            return new WipeAllResponse(false, steps);
        }

        return new WipeAllResponse(true, steps);
    }

    /** Runs one step, appends its outcome, and returns whether it succeeded. */
    private boolean attemptStep(List<WipeAllResponse.Step> steps, String service, StepAction action) {
        try {
            Map<String, Long> counts = action.run();
            steps.add(new WipeAllResponse.Step(service, true, "Wiped successfully.", counts));
            return true;
        } catch (DownstreamWipeException e) {
            log.error("[WipeAll] {} failed, stopping here: {}", service, e.getMessage());
            steps.add(new WipeAllResponse.Step(service, false, e.getMessage(), null));
            return false;
        } catch (RuntimeException e) {
            log.error("[WipeAll] {} failed unexpectedly, stopping here", service, e);
            steps.add(new WipeAllResponse.Step(service, false, e.getMessage(), null));
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Long> toLongMap(Map<String, Object> raw) {
        Map<String, Long> result = new LinkedHashMap<>();
        raw.forEach((key, value) -> {
            if (value instanceof Number number) {
                result.put(key, number.longValue());
            } else if (value instanceof Map) {
                // internalAuthDeletedCounts/deletedCounts nest a second map -
                // flatten with a prefix so every count is still visible at
                // one level.
                ((Map<String, Object>) value).forEach((innerKey, innerValue) -> {
                    if (innerValue instanceof Number number) {
                        result.put(key + "." + innerKey, number.longValue());
                    }
                });
            }
        });
        return result;
    }

    @FunctionalInterface
    private interface StepAction {
        Map<String, Long> run();
    }
}
