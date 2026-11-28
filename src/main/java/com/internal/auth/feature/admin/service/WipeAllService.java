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

/** Orchestrates a full wipe across this service and the downstream apps. */
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
