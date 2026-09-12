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
