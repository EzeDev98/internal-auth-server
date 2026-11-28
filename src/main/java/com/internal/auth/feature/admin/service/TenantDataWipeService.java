package com.internal.auth.feature.admin.service;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.feature.audit.repository.AuditLogRepository;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.EmailVerificationTokenRepository;
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

/** Deletes every row belonging to a single tenant. */
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
        counts.put("phoneVerificationOtps", phoneVerificationOtpRepository.deleteAllByClientApplicationId(clientApplicationId));
        counts.put("auditLogs", auditLogRepository.deleteAllByClientApplicationId(clientApplicationId));
        counts.put("users", userRepository.deleteAllByClientApplicationId(clientApplicationId));

        log.warn("[TenantReset] Wiped tenant appId={} clientApplicationId={}. counts={}", appId, clientApplicationId, counts);

        return counts;
    }
}
