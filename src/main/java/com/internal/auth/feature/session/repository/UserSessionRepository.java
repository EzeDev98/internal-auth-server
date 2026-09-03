package com.internal.auth.feature.session.repository;

import com.internal.auth.feature.session.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Step 11B: findByPhoneNumberAndIsActiveTrue/findByPhoneNumber removed -
 * phoneNumber is no longer a lookup key (see UserSession's class Javadoc).
 * findByUserIdAndIsActiveTrue replaces them as the one active-session
 * lookup, since userId is always present.
 */
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByTokenHash(String tokenHash);
    Optional<UserSession> findByUserIdAndIsActiveTrue(Long userId);
}
