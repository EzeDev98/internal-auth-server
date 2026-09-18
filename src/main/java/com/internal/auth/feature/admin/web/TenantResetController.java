package com.internal.auth.feature.admin.web;

import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.feature.admin.dto.request.TenantWipeRequest;
import com.internal.auth.feature.admin.dto.request.WipeAllRequest;
import com.internal.auth.feature.admin.dto.response.TenantWipeResponse;
import com.internal.auth.feature.admin.dto.response.WipeAllResponse;
import com.internal.auth.feature.admin.security.TenantResetAuthorizer;
import com.internal.auth.feature.admin.service.TenantDataWipeService;
import com.internal.auth.feature.admin.service.WipeAllService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Danger-zone endpoint: wipes every row belonging to one tenant
 * (ClientApplication), called by that tenant's own admin wipe endpoint
 * (e.g. SyncPoint's {@code POST /admin/reset/wipe} -> this app's
 * {@code POST /admin/reset/wipe-tenant}), or directly by an operator.
 * <p>
 * Deliberately thin, mirroring SyncPoint's own AdminResetController: it
 * authorizes via {@link TenantResetAuthorizer}, delegates the work to
 * {@link TenantDataWipeService}, and returns the report. The path is opened
 * in {@code WebSecurityConfig} (no JWT required) since the secret is the
 * guard - the same reasoning SyncPoint's own reset endpoint javadoc gives.
 */
@Slf4j
@RestController
@RequestMapping("${app.title}")
@RequiredArgsConstructor
@Tag(name = "Admin Reset API", description = "Destructive maintenance — wipes all data belonging to one tenant")
public class TenantResetController {

    private final TenantResetAuthorizer tenantResetAuthorizer;
    private final TenantDataWipeService tenantDataWipeService;
    private final WipeAllService wipeAllService;

    @PostMapping("/admin/reset/wipe-tenant")
    public ResponseEntity<InternalAuthApiResponse<TenantWipeResponse>> wipeTenant(
            @RequestHeader(value = "X-Reset-Secret", required = false) String providedSecret,
            @RequestBody(required = false) TenantWipeRequest request) {

        String appId = request != null ? request.getAppId() : null;
        String confirmation = request != null ? request.getConfirmation() : null;

        tenantResetAuthorizer.authorize(providedSecret, appId, confirmation);

        log.warn("[TenantReset] AUTHORIZED wipe starting for appId={}", appId);

        Map<String, Long> deletedCounts = tenantDataWipeService.wipeTenant(appId);

        TenantWipeResponse response = new TenantWipeResponse(appId, deletedCounts);
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
}
