package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

    /** Backs TenantDataWipeService - this table has no clientApplicationId column, only userId. */
    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}
