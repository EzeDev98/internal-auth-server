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

/** Endpoint for wiping a single tenant's data. */
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
