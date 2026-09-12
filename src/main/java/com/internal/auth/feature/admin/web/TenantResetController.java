package com.internal.auth.feature.admin.web;

import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.feature.admin.dto.request.TenantWipeRequest;
import com.internal.auth.feature.admin.dto.response.TenantWipeResponse;
import com.internal.auth.feature.admin.security.TenantResetAuthorizer;
import com.internal.auth.feature.admin.service.TenantDataWipeService;
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
}
