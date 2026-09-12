#!/bin/bash
set -e

mkdir -p src/main/java/com/internal/auth/feature/admin/dto/request
mkdir -p src/main/java/com/internal/auth/feature/admin/dto/response
mkdir -p src/main/java/com/internal/auth/feature/admin/security
mkdir -p src/main/java/com/internal/auth/feature/admin/service
mkdir -p src/main/java/com/internal/auth/feature/admin/web

cat > src/main/java/com/internal/auth/common/exception/InvalidResetSecretException.java << 'EOF'
package com.internal.auth.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown by {@link com.internal.auth.feature.admin.security.TenantResetAuthorizer}
 * when the caller's X-Reset-Secret header is missing/invalid, or when the
 * tenant-wipe endpoint is disabled entirely (no admin.reset.secret configured).
 * Mirrors SyncPoint's own UnauthorizedException usage for its local
 * /admin/reset/wipe endpoint - same guard, same status, same "don't tell the
 * caller which part was wrong" posture as InvalidClientCredentialsException.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidResetSecretException extends RuntimeException {
    public InvalidResetSecretException(String message) {
        super(message);
    }
}
EOF

cat > src/main/java/com/internal/auth/feature/admin/dto/request/TenantWipeRequest.java << 'EOF'
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
EOF

cat > src/main/java/com/internal/auth/feature/admin/dto/response/TenantWipeResponse.java << 'EOF'
package com.internal.auth.feature.admin.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/**
 * Result of a per-tenant wipe: pre-delete row counts per table, keyed the
 * same way SyncPoint's own DatabaseResetService.ResetResult is.
 *
 * @see com.internal.auth.feature.admin.web.TenantResetController
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TenantWipeResponse {
    private String appId;
    private Map<String, Long> deletedCounts;
}
EOF

cat > src/main/java/com/internal/auth/feature/admin/security/TenantResetAuthorizer.java << 'EOF'
package com.internal.auth.feature.admin.security;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.InvalidResetSecretException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guards the per-tenant destructive data wipe, mirroring SyncPoint's own
 * ResetAuthorizer pattern (secret + confirmation phrase, both required),
 * plus the one field that pattern didn't need: which tenant to wipe.
 * <ul>
 *   <li><b>Secret.</b> The caller must present {@code X-Reset-Secret}
 *       matching {@code admin.reset.secret}. A blank/unset property disables
 *       the endpoint entirely. Constant-time comparison.</li>
 *   <li><b>appId.</b> Required - identifies which ClientApplication's data
 *       to wipe. Never defaulted or inferred.</li>
 *   <li><b>Confirmation phrase.</b> The body must carry the exact phrase, so
 *       a call holding only the secret cannot fire by accident or replay.</li>
 * </ul>
 */
@Slf4j
@Component
public class TenantResetAuthorizer {

    private static final String REQUIRED_CONFIRMATION = "WIPE-EVERYTHING";

    private final String configuredSecret;

    public TenantResetAuthorizer(@Value("${admin.reset.secret:}") String configuredSecret) {
        this.configuredSecret = configuredSecret;
    }

    /**
     * @param providedSecret value of the {@code X-Reset-Secret} header
     * @param appId          the clientId to wipe, from the request body
     * @param confirmation   confirmation phrase from the request body
     * @throws InvalidResetSecretException if the endpoint is disabled or the secret is missing/invalid
     * @throws BadRequestException         if appId or the confirmation phrase is missing/incorrect
     */
    public void authorize(String providedSecret, String appId, String confirmation) {
        if (configuredSecret == null || configuredSecret.isBlank()) {
            log.warn("[TenantReset] Rejected — endpoint disabled (no admin.reset.secret configured)");
            throw new InvalidResetSecretException("Tenant reset endpoint is disabled. Set admin.reset.secret to enable it.");
        }

        if (!secretMatches(providedSecret)) {
            log.warn("[TenantReset] Rejected — missing or invalid X-Reset-Secret");
            throw new InvalidResetSecretException("Invalid or missing reset secret.");
        }

        if (appId == null || appId.isBlank()) {
            log.warn("[TenantReset] Rejected — missing appId");
            throw new BadRequestException("appId is required.");
        }

        if (!REQUIRED_CONFIRMATION.equals(confirmation)) {
            log.warn("[TenantReset] Rejected — confirmation phrase missing or incorrect for appId={}", appId);
            throw new BadRequestException("Confirmation required: send {\"confirmation\": \"" + REQUIRED_CONFIRMATION + "\"} in the body.");
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
}
EOF

cat > src/main/java/com/internal/auth/feature/admin/service/TenantDataWipeService.java << 'EOF'
package com.internal.auth.feature.admin.service;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.feature.audit.repository.AuditLogRepository;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.EmailVerificationTokenRepository;
import com.internal.auth.feature.identity.repository.LoginMfaOtpRepository;
import com.internal.auth.feature.identity.repository.PhoneVerificationOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.passwordreset.repository.PasswordResetOtpRepository;
import com.internal.auth.feature.passwordreset.repository.PasswordResetTokenRepository;
import com.internal.auth.feature.rbac.repository.UserPermissionGroupRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Destructive maintenance: wipes every row belonging to one tenant
 * (ClientApplication), so an integrating app's own admin wipe endpoint
 * (e.g. SyncPoint's {@code /admin/reset/wipe}) can call down into this one
 * and leave both sides clean together.
 * <p>
 * The ClientApplication row itself is NOT deleted - it's the tenant's
 * registration, not its data (same reasoning SyncPoint's own
 * DatabaseResetService uses to preserve system_wallet by default). Only
 * rows scoped to that tenant are removed.
 * <p>
 * Guarded entirely by {@code TenantResetAuthorizer} at the controller -
 * nothing here re-checks the secret/confirmation. Do not wire a second
 * caller to this service without reproducing that guard.
 *
 * <h2>Delete order</h2>
 * Children first, so foreign keys are never violated: RBAC join rows, then
 * every token/OTP table, then the users themselves. Roles/PermissionGroups
 * are left untouched - Role/PermissionGroup's own client-application scope
 * is data-model-only and not enforced anywhere yet, so there's nothing
 * tenant-specific to safely remove from those tables today.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TenantDataWipeService {

    private final ClientApplicationRepository clientApplicationRepository;
    private final UserRepository userRepository;
    private final UserRolesRepository userRolesRepository;
    private final UserPermissionGroupRepository userPermissionGroupRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordResetOtpRepository passwordResetOtpRepository;
    private final LoginMfaOtpRepository loginMfaOtpRepository;
    private final PhoneVerificationOtpRepository phoneVerificationOtpRepository;
    private final AuditLogRepository auditLogRepository;

    @Transactional
    public Map<String, Long> wipeTenant(String appId) {
        ClientApplication client = clientApplicationRepository.findByClientId(appId)
                .orElseThrow(() -> new BadRequestException("Unknown appId: " + appId));

        Long clientApplicationId = client.getId();

        List<User> users = userRepository.findAllByClientApplicationId(clientApplicationId);
        List<Long> userIds = users.stream().map(User::getId).toList();

        Map<String, Long> counts = new LinkedHashMap<>();

        if (!userIds.isEmpty()) {
            counts.put("userRoles", userRolesRepository.deleteAllByUser_IdIn(userIds));
            counts.put("userPermissionGroups", userPermissionGroupRepository.deleteAllByUser_IdIn(userIds));
            counts.put("emailVerificationTokens", emailVerificationTokenRepository.deleteAllByUserIdIn(userIds));
            counts.put("passwordResetTokens", passwordResetTokenRepository.deleteAllByUserIdIn(userIds));
            counts.put("userSessions", userSessionRepository.deleteAllByUserIdIn(userIds));
        } else {
            counts.put("userRoles", 0L);
            counts.put("userPermissionGroups", 0L);
            counts.put("emailVerificationTokens", 0L);
            counts.put("passwordResetTokens", 0L);
            counts.put("userSessions", 0L);
        }

        counts.put("passwordResetOtps", passwordResetOtpRepository.deleteAllByClientApplicationId(clientApplicationId));
        counts.put("loginMfaOtps", loginMfaOtpRepository.deleteAllByClientApplicationId(clientApplicationId));
        counts.put("phoneVerificationOtps", phoneVerificationOtpRepository.deleteAllByClientApplicationId(clientApplicationId));
        counts.put("auditLogs", auditLogRepository.deleteAllByClientApplicationId(clientApplicationId));
        counts.put("users", userRepository.deleteAllByClientApplicationId(clientApplicationId));

        log.warn("[TenantReset] Wiped tenant appId={} clientApplicationId={}. counts={}", appId, clientApplicationId, counts);

        return counts;
    }
}
EOF

cat > src/main/java/com/internal/auth/feature/admin/web/TenantResetController.java << 'EOF'
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
EOF

echo "Created 6 new files. Now patching 9 existing files..."

python3 << 'PYEOF'
import io

def patch(path, old, new, label):
    with io.open(path, "r", encoding="utf-8") as f:
        content = f.read()
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"ABORT [{label}]: expected 1 match in {path}, found {count}. File may have already been patched or has diverged — check manually.")
    content = content.replace(old, new, 1)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Patched: {path} ({label})")

# 1. application.properties — add admin.reset.secret
p = "src/main/resources/application.properties"
with io.open(p, "r", encoding="utf-8") as f:
    content = f.read()
if "admin.reset.secret" not in content:
    content = content.rstrip("\n") + "\n\n# ---------------------------------------------------------------------------\n# Danger-zone per-tenant data wipe (TenantResetController). Blank disables\n# the endpoint entirely. Set ADMIN_RESET_SECRET to enable it.\n# ---------------------------------------------------------------------------\nadmin.reset.secret=${ADMIN_RESET_SECRET:}\n"
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Patched: {p} (added admin.reset.secret)")
else:
    print(f"Skipped: {p} (admin.reset.secret already present)")

# 2. WebSecurityConfig — permitAll the new endpoint
patch(
    "src/main/java/com/internal/auth/config/auth/WebSecurityConfig.java",
    '                                appTitle + "/otp/**"\n                        ).permitAll()',
    '                                appTitle + "/otp/**"\n                        ).permitAll()\n\n                        // Danger-zone per-tenant data wipe. Opened here so it can be called\n                        // without a JWT - guarded instead by a required X-Reset-Secret plus a\n                        // confirmation phrase, and inert unless admin.reset.secret is configured.\n                        // See TenantResetController.\n                        .requestMatchers(HttpMethod.POST, appTitle + "/admin/reset/wipe-tenant").permitAll()',
    "WebSecurityConfig permitAll"
)

# 3. UserRepository — findAllByClientApplicationId + deleteAllByClientApplicationId
patch(
    "src/main/java/com/internal/auth/feature/identity/repository/UserRepository.java",
    '''    Page<User> searchForAdmin(@Param("clientApplicationId") Long clientApplicationId,
                               @Param("enabled") Boolean enabled,
                               @Param("search") String search,
                               Pageable pageable);
}''',
    '''    Page<User> searchForAdmin(@Param("clientApplicationId") Long clientApplicationId,
                               @Param("enabled") Boolean enabled,
                               @Param("search") String search,
                               Pageable pageable);

    /** Backs TenantDataWipeService - every user in one tenant, so their ids can be collected before cascading deletes. */
    List<User> findAllByClientApplicationId(Long clientApplicationId);

    /** Backs TenantDataWipeService - deletes the users themselves once every child table is cleared. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}''',
    "UserRepository"
)

# 4. UserRolesRepository — deleteAllByUser_IdIn
patch(
    "src/main/java/com/internal/auth/feature/rbac/repository/UserRolesRepository.java",
    '''    @Query("SELECT DISTINCT userRole.user FROM UserRole userRole WHERE userRole.role.id = :roleId")
    List<User> findUsersByRoleId(@Param("roleId") Long roleId);
}''',
    '''    @Query("SELECT DISTINCT userRole.user FROM UserRole userRole WHERE userRole.role.id = :roleId")
    List<User> findUsersByRoleId(@Param("roleId") Long roleId);

    /** Backs TenantDataWipeService - batch equivalent of deleteAllByUser_Id above. */
    long deleteAllByUser_IdIn(List<Long> userIds);
}''',
    "UserRolesRepository"
)

# 5. UserPermissionGroupRepository — deleteAllByUser_IdIn
patch(
    "src/main/java/com/internal/auth/feature/rbac/repository/UserPermissionGroupRepository.java",
    '''    @Query("SELECT DISTINCT userPermissionGroup.permissionGroup FROM UserPermissionGroup userPermissionGroup " +
            "WHERE userPermissionGroup.user.username = :username")
    List<PermissionGroup> findPermissionGroupsByUsername(String username);
}''',
    '''    @Query("SELECT DISTINCT userPermissionGroup.permissionGroup FROM UserPermissionGroup userPermissionGroup " +
            "WHERE userPermissionGroup.user.username = :username")
    List<PermissionGroup> findPermissionGroupsByUsername(String username);

    /** Backs TenantDataWipeService - batch equivalent of deleteAllByUser_Id above. */
    long deleteAllByUser_IdIn(List<Long> userIds);
}''',
    "UserPermissionGroupRepository"
)

# 6. EmailVerificationTokenRepository
patch(
    "src/main/java/com/internal/auth/feature/identity/repository/EmailVerificationTokenRepository.java",
    '''public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByTokenHash(String tokenHash);
}''',
    '''public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

    /** Backs TenantDataWipeService - this table has no clientApplicationId column, only userId. */
    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}''',
    "EmailVerificationTokenRepository"
)

# 7. PasswordResetTokenRepository
patch(
    "src/main/java/com/internal/auth/feature/passwordreset/repository/PasswordResetTokenRepository.java",
    '''public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);
}''',
    '''public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    /** Backs TenantDataWipeService - this table has no clientApplicationId column, only userId. */
    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}''',
    "PasswordResetTokenRepository"
)

# 8. UserSessionRepository (internal-auth-server's own, session feature)
patch(
    "src/main/java/com/internal/auth/feature/session/repository/UserSessionRepository.java",
    '''    Page<UserSession> searchForAdmin(@Param("userId") Long userId,
                                      @Param("active") Boolean active,
                                      @Param("ipAddress") String ipAddress,
                                      @Param("device") String device,
                                      Pageable pageable);
}''',
    '''    Page<UserSession> searchForAdmin(@Param("userId") Long userId,
                                      @Param("active") Boolean active,
                                      @Param("ipAddress") String ipAddress,
                                      @Param("device") String device,
                                      Pageable pageable);

    /** Backs TenantDataWipeService - this table has no clientApplicationId column, only userId. */
    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}''',
    "UserSessionRepository"
)

# 9. PasswordResetOtpRepository / LoginMfaOtpRepository / PhoneVerificationOtpRepository / AuditLogRepository
patch(
    "src/main/java/com/internal/auth/feature/passwordreset/repository/PasswordResetOtpRepository.java",
    '''    Optional<PasswordResetOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, ResetStatus status);
}''',
    '''    Optional<PasswordResetOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, ResetStatus status);

    /** Backs TenantDataWipeService. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}''',
    "PasswordResetOtpRepository"
)

patch(
    "src/main/java/com/internal/auth/feature/identity/repository/LoginMfaOtpRepository.java",
    '''    Optional<LoginMfaOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, ResetStatus status);
}''',
    '''    Optional<LoginMfaOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(String phoneNumber, Long clientApplicationId, ResetStatus status);

    /** Backs TenantDataWipeService. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}''',
    "LoginMfaOtpRepository"
)

patch(
    "src/main/java/com/internal/auth/feature/identity/repository/PhoneVerificationOtpRepository.java",
    '''    Optional<PhoneVerificationOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
            String phoneNumber, Long clientApplicationId, ResetStatus status);
}''',
    '''    Optional<PhoneVerificationOtp> findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
            String phoneNumber, Long clientApplicationId, ResetStatus status);

    /** Backs TenantDataWipeService. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}''',
    "PhoneVerificationOtpRepository"
)

patch(
    "src/main/java/com/internal/auth/feature/audit/repository/AuditLogRepository.java",
    '''public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}''',
    '''public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    /** Backs TenantDataWipeService. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}''',
    "AuditLogRepository"
)

print("All patches applied successfully.")
PYEOF

echo ""
echo "Done. Set ADMIN_RESET_SECRET in this app's environment to enable the endpoint (blank = disabled)."
