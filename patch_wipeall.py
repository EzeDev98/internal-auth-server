import pathlib

base = pathlib.Path("src/main/java/com/internal/auth/feature/admin")

# --- 1) NEW: DownstreamWipeException ---
(base / "client").mkdir(parents=True, exist_ok=True)
(base / "client" / "DownstreamWipeException.java").write_text("""package com.internal.auth.feature.admin.client;

/**
 * Thrown by {@link DownstreamAppWipeClient} when a call to SyncPoint's or
 * Notare's own wipe endpoint fails - bad/missing secret on either side,
 * a rejected confirmation, the app being unreachable, or a 5xx from its
 * own wipe logic. Always caught by WipeAllService, which turns it into a
 * WipeAllResponse.Step(success=false, message=...) rather than letting it
 * reach GlobalExceptionHandler - see WipeAllService's class Javadoc for
 * why the whole operation stops there instead of continuing.
 */
public class DownstreamWipeException extends RuntimeException {
    public DownstreamWipeException(String message) {
        super(message);
    }
}
""")
print("Created client/DownstreamWipeException.java")

# --- 2) NEW: DownstreamAppWipeClient ---
(base / "client" / "DownstreamAppWipeClient.java").write_text("""package com.internal.auth.feature.admin.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Outbound calls to SyncPoint's and Notare's own existing admin wipe
 * endpoints, for WipeAllService's cross-service "wipe everything"
 * orchestration (Settings page danger zone). This is the reverse
 * direction of InternalAuthClient in SyncPoint's own codebase (which
 * calls INTO this app) - internal-auth is the one initiating here, since
 * it's the app meant to be the final authority for a full-environment
 * wipe.
 * <p>
 * Each app's own wipe endpoint keeps working completely unchanged and
 * independently callable exactly as it is today (SyncPoint's own admin
 * can still wipe just SyncPoint + its own internal-auth tenant data
 * without touching Notare) - this class only ever ADDS a caller, it
 * never modifies what either endpoint does.
 * <p>
 * A generous read timeout (60s) is deliberate: both apps are commonly
 * deployed on Render's free tier, which spins a service down after
 * inactivity (see internal-auth-server's own KeepAliveJob) - the first
 * request after a cold start can itself take several seconds before the
 * wipe logic even begins, on top of however long the wipe itself takes.
 * The connect timeout stays short (10s) since an unreachable host should
 * fail fast rather than hang for a minute.
 */
@Slf4j
@Component
public class DownstreamAppWipeClient {

    private static final String SYNC_POINT_CONFIRMATION = "WIPE-EVERYTHING";

    private final RestClient syncPointClient;
    private final RestClient notareClient;
    private final String syncPointSecret;
    private final String notareSecret;
    private final ObjectMapper objectMapper;

    public DownstreamAppWipeClient(
            @Value("${sync-point.wipe.base-url}") String syncPointBaseUrl,
            @Value("${sync-point.wipe.secret:}") String syncPointSecret,
            @Value("${notare.wipe.base-url}") String notareBaseUrl,
            @Value("${notare.wipe.secret:}") String notareSecret,
            ObjectMapper objectMapper) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(10_000);
        requestFactory.setReadTimeout(60_000);

        this.syncPointClient = RestClient.builder().baseUrl(syncPointBaseUrl).requestFactory(requestFactory).build();
        this.notareClient = RestClient.builder().baseUrl(notareBaseUrl).requestFactory(requestFactory).build();
        this.syncPointSecret = syncPointSecret;
        this.notareSecret = notareSecret;
        this.objectMapper = objectMapper;
    }

    /**
     * Calls SyncPoint's existing POST /admin/reset/wipe - wipes SyncPoint's
     * own database AND (via SyncPoint's own existing downstream call)
     * every internal-auth-server record scoped to its clientApplicationId,
     * in one round trip. Returns SyncPoint's own reported deleted-row
     * counts (both its local ones and internal-auth's, nested under
     * "internalAuthDeletedCounts" - see AdminResetController on
     * SyncPoint's side) so the admin sees exactly what was removed.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> wipeSyncPoint(boolean includeSystemWallet) {
        if (syncPointSecret == null || syncPointSecret.isBlank()) {
            throw new DownstreamWipeException("sync-point.wipe.secret is not configured - refusing to call SyncPoint's wipe endpoint.");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("confirmation", SYNC_POINT_CONFIRMATION);
        body.put("includeSystemWallet", includeSystemWallet);

        try {
            JsonNode response = syncPointClient.post()
                    .uri("/admin/reset/wipe")
                    .header("X-Reset-Secret", syncPointSecret)
                    .body(body)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new DownstreamWipeException("SyncPoint wipe failed: " + extractMessage(res));
                    })
                    .body(JsonNode.class);
            JsonNode data = response != null ? response.get("data") : null;
            return data != null ? objectMapper.convertValue(data, Map.class) : Map.of();
        } catch (DownstreamWipeException e) {
            throw e;
        } catch (Exception e) {
            log.error("[WipeAll] SyncPoint wipe call failed", e);
            throw new DownstreamWipeException("Could not reach SyncPoint: " + e.getMessage());
        }
    }

    /**
     * Calls Notare's existing POST /admin/database/wipe - truncates every
     * table in Notare's own database. Notare has no concept of per-tenant
     * scoping and no integration with internal-auth-server today (see
     * WipeAllService's class Javadoc), so unlike SyncPoint there is no
     * downstream internal-auth call for this to trigger.
     */
    public void wipeNotare() {
        if (notareSecret == null || notareSecret.isBlank()) {
            throw new DownstreamWipeException("notare.wipe.secret is not configured - refusing to call Notare's wipe endpoint.");
        }
        try {
            notareClient.post()
                    .uri("/admin/database/wipe")
                    .header("X-Admin-Secret", notareSecret)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new DownstreamWipeException("Notare wipe failed: " + extractMessage(res));
                    })
                    .toBodilessEntity();
        } catch (DownstreamWipeException e) {
            throw e;
        } catch (Exception e) {
            log.error("[WipeAll] Notare wipe call failed", e);
            throw new DownstreamWipeException("Could not reach Notare: " + e.getMessage());
        }
    }

    /**
     * SyncPoint returns its own InternalAuthApiResponse-shaped JSON
     * ({"message": "..."}), Notare returns a plain text body - this tries
     * JSON first and falls back to the raw body so either shape yields a
     * readable message instead of a stack trace fragment.
     */
    private String extractMessage(ClientHttpResponse response) {
        try {
            String raw = StreamUtils.copyToString(response.getBody(), StandardCharsets.UTF_8);
            if (raw.isBlank()) {
                return "HTTP " + response.getStatusCode().value();
            }
            try {
                JsonNode parsed = objectMapper.readTree(raw);
                if (parsed.has("message") && !parsed.get("message").isNull()) {
                    return parsed.get("message").asText();
                }
            } catch (Exception ignored) {
                // Not JSON - fall through to the raw body.
            }
            return raw;
        } catch (Exception e) {
            return "HTTP " + safeStatus(response) + " (could not read response body)";
        }
    }

    private int safeStatus(ClientHttpResponse response) {
        try {
            return response.getStatusCode().value();
        } catch (Exception e) {
            return -1;
        }
    }
}
""")
print("Created client/DownstreamAppWipeClient.java")

# --- 3) NEW: WipeAllRequest ---
(base / "dto" / "request" / "WipeAllRequest.java").write_text("""package com.internal.auth.feature.admin.dto.request;

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
""")
print("Created dto/request/WipeAllRequest.java")

# --- 4) NEW: WipeAllResponse ---
(base / "dto" / "response" / "WipeAllResponse.java").write_text("""package com.internal.auth.feature.admin.dto.response;

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
""")
print("Created dto/response/WipeAllResponse.java")

# --- 5) NEW: WipeAllService ---
(base / "service" / "WipeAllService.java").write_text("""package com.internal.auth.feature.admin.service;

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
""")
print("Created service/WipeAllService.java")

# --- 6) EDIT: TenantResetAuthorizer - add authorizeWipeAll ---
f_auth = base / "security" / "TenantResetAuthorizer.java"
s_auth = f_auth.read_text()

old_auth = """    private boolean secretMatches(String providedSecret) {
        if (providedSecret == null) {
            return false;
        }
        byte[] expected = configuredSecret.getBytes(StandardCharsets.UTF_8);
        byte[] actual = providedSecret.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }
}"""
new_auth = """    /**
     * Guards the top-level "wipe everything" endpoint (SyncPoint + Notare +
     * internal-auth) - same secret and confirmation phrase as {@link
     * #authorize}, just without an appId, since this always wipes every
     * connected app rather than one tenant.
     *
     * @param providedSecret value of the {@code X-Reset-Secret} header
     * @param confirmation   confirmation phrase from the request body
     * @throws InvalidResetSecretException if the endpoint is disabled or the secret is missing/invalid
     * @throws BadRequestException         if the confirmation phrase is missing/incorrect
     */
    public void authorizeWipeAll(String providedSecret, String confirmation) {
        if (configuredSecret == null || configuredSecret.isBlank()) {
            log.warn("[WipeAll] Rejected — endpoint disabled (no admin.reset.secret configured)");
            throw new InvalidResetSecretException("Wipe-all endpoint is disabled. Set admin.reset.secret to enable it.");
        }

        if (!secretMatches(providedSecret)) {
            log.warn("[WipeAll] Rejected — missing or invalid X-Reset-Secret");
            throw new InvalidResetSecretException("Invalid or missing reset secret.");
        }

        if (!REQUIRED_CONFIRMATION.equals(confirmation)) {
            log.warn("[WipeAll] Rejected — confirmation phrase missing or incorrect");
            throw new BadRequestException("Confirmation required: send {\\"confirmation\\": \\"" + REQUIRED_CONFIRMATION + "\\"} in the body.");
        }
    }

    private boolean secretMatches(String providedSecret) {
        if (providedSecret == null) {
            return false;
        }
        byte[] expected = configuredSecret.getBytes(StandardCharsets.UTF_8);
        byte[] actual = providedSecret.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }
}"""
assert s_auth.count(old_auth) == 1, "authorizer anchor not found or not unique"
s_auth = s_auth.replace(old_auth, new_auth)
f_auth.write_text(s_auth)
print(f"Patched {f_auth}")

# --- 7) EDIT: TenantResetController - add wipe-all endpoint ---
f_ctrl = base / "web" / "TenantResetController.java"
s_ctrl = f_ctrl.read_text()

old_ctrl_imports = """import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.feature.admin.dto.request.TenantWipeRequest;
import com.internal.auth.feature.admin.dto.response.TenantWipeResponse;
import com.internal.auth.feature.admin.security.TenantResetAuthorizer;
import com.internal.auth.feature.admin.service.TenantDataWipeService;"""
new_ctrl_imports = """import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.feature.admin.dto.request.TenantWipeRequest;
import com.internal.auth.feature.admin.dto.request.WipeAllRequest;
import com.internal.auth.feature.admin.dto.response.TenantWipeResponse;
import com.internal.auth.feature.admin.dto.response.WipeAllResponse;
import com.internal.auth.feature.admin.security.TenantResetAuthorizer;
import com.internal.auth.feature.admin.service.TenantDataWipeService;
import com.internal.auth.feature.admin.service.WipeAllService;"""
assert s_ctrl.count(old_ctrl_imports) == 1, "controller import anchor not found or not unique"
s_ctrl = s_ctrl.replace(old_ctrl_imports, new_ctrl_imports)

old_ctrl_field = """    private final TenantResetAuthorizer tenantResetAuthorizer;
    private final TenantDataWipeService tenantDataWipeService;"""
new_ctrl_field = """    private final TenantResetAuthorizer tenantResetAuthorizer;
    private final TenantDataWipeService tenantDataWipeService;
    private final WipeAllService wipeAllService;"""
assert s_ctrl.count(old_ctrl_field) == 1, "controller field anchor not found or not unique"
s_ctrl = s_ctrl.replace(old_ctrl_field, new_ctrl_field)

old_ctrl_end = """        TenantWipeResponse response = new TenantWipeResponse(appId, deletedCounts);
        return ResponseEntity.ok(InternalAuthApiResponse.success("Tenant data wiped.", response));
    }
}"""
new_ctrl_end = """        TenantWipeResponse response = new TenantWipeResponse(appId, deletedCounts);
        return ResponseEntity.ok(InternalAuthApiResponse.success("Tenant data wiped.", response));
    }

    /**
     * Settings-page "wipe everything" danger zone: SyncPoint, Notare, and
     * internal-auth's own data, together - see {@link WipeAllService}'s
     * class Javadoc for the full reasoning (order, stop-on-first-failure,
     * why Notare's own internal-auth tenant step is normally a no-op
     * today). Does not replace or change SyncPoint's own
     * {@code /admin/reset/wipe} or Notare's own
     * {@code /admin/database/wipe} - both keep working unchanged, callable
     * directly, independent of this endpoint.
     */
    @PostMapping("/admin/reset/wipe-all")
    public ResponseEntity<InternalAuthApiResponse<WipeAllResponse>> wipeAll(
            @RequestHeader(value = "X-Reset-Secret", required = false) String providedSecret,
            @RequestBody(required = false) WipeAllRequest request) {

        String confirmation = request != null ? request.getConfirmation() : null;
        boolean includeSystemWallet = request != null && Boolean.TRUE.equals(request.getIncludeSystemWallet());

        tenantResetAuthorizer.authorizeWipeAll(providedSecret, confirmation);

        log.warn("[WipeAll] AUTHORIZED wipe-everything starting. includeSystemWallet={}", includeSystemWallet);

        WipeAllResponse response = wipeAllService.wipeEverything(includeSystemWallet);

        String message = response.isCompletedFully()
                ? "Everything wiped: SyncPoint, Notare, and internal-auth."
                : "Wipe stopped after a failure - see steps for details.";
        return ResponseEntity.ok(InternalAuthApiResponse.success(message, response));
    }
}"""
assert s_ctrl.count(old_ctrl_end) == 1, "controller end anchor not found or not unique"
s_ctrl = s_ctrl.replace(old_ctrl_end, new_ctrl_end)

f_ctrl.write_text(s_ctrl)
print(f"Patched {f_ctrl}")

# --- 8) EDIT: application.properties - add new config block ---
f_props = pathlib.Path("src/main/resources/application.properties")
s_props = f_props.read_text()

old_props = """admin.reset.secret=${ADMIN_RESET_SECRET:}"""
new_props = """admin.reset.secret=${ADMIN_RESET_SECRET:}

# ---------------------------------------------------------------------------
# Settings-page "wipe everything" danger zone (WipeAllService): internal-auth
# calling OUT to SyncPoint's and Notare's own existing admin wipe endpoints,
# then internal-auth's own tenant data for either one if it's ever
# registered here as a ClientApplication. Guarded by admin.reset.secret
# above (see TenantResetAuthorizer#authorizeWipeAll) - the two secrets below
# are different: they authenticate internal-auth TO those other apps, not
# the admin calling internal-auth. Blank by default (fail closed, same
# posture as admin.reset.secret) - set both once SyncPoint's/Notare's own
# reset secrets are known.
# ---------------------------------------------------------------------------
sync-point.wipe.base-url=${SYNC_POINT_WIPE_BASE_URL:http://localhost:2000/api/v1}
sync-point.wipe.secret=${SYNC_POINT_WIPE_SECRET:}
notare.wipe.base-url=${NOTARE_WIPE_BASE_URL:http://localhost:2001/api/v1}
notare.wipe.secret=${NOTARE_WIPE_SECRET:}
# clientId Notare would be registered under in THIS app's client_applications
# table, if/when it's migrated onto internal-auth (see WipeAllService's
# class Javadoc) - not assumed to exist today.
notare.internal-auth-client-id=${NOTARE_INTERNAL_AUTH_CLIENT_ID:notare}"""
assert s_props.count(old_props) == 1, "properties anchor not found or not unique"
s_props = s_props.replace(old_props, new_props)
f_props.write_text(s_props)
print(f"Patched {f_props}")
