package com.internal.auth.feature.passwordreset.repository;

import com.internal.auth.feature.passwordreset.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Repository for password reset tokens. */
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}
