package com.internal.auth.feature.session.repository;

import com.internal.auth.feature.session.model.UserSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/**
 * Step 11B: findByPhoneNumberAndIsActiveTrue/findByPhoneNumber removed -
 * phoneNumber is no longer a lookup key (see UserSession's class Javadoc).
 * userId is the active-session lookup key, since it is always present.
 *
 * Step 17h: a user may hold several active sessions (one per device, up to
 * the client's max_active_sessions), so the active lookup returns a list.
 */
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByTokenHash(String tokenHash);
    List<UserSession> findAllByUserIdAndIsActiveTrue(Long userId);

    /**
     * Step 2E (React Admin Client plan v4): backs GET
     * ${app.title}/admin/sessions - the admin session directory's
     * list/filter. Every filter is nullable to mean "don't filter on
     * this"; ipAddress/device match as a case-insensitive substring.
     */
    // CAST(... AS string) on :ipAddress/:device: same fix, same reason, as
    // UserRepository#searchForAdmin's :search cast - a parameter used only
    // inside LOWER(CONCAT(...)), never compared directly to a typed
    // column, gets its type inferred as bytea by Hibernate 7 + pgjdbc
    // instead of text, and lower(bytea) doesn't exist in Postgres. Fixes
    // the same "service temporarily unavailable" 503 on the Sessions page.
    @Query("SELECT s FROM UserSession s WHERE " +
            "(:userId IS NULL OR s.userId = :userId) AND " +
            "(:active IS NULL OR s.isActive = :active) AND " +
            "(:ipAddress IS NULL OR LOWER(s.ipAddress) LIKE LOWER(CONCAT('%', CAST(:ipAddress AS string), '%'))) AND " +
            "(:device IS NULL OR LOWER(s.userAgent) LIKE LOWER(CONCAT('%', CAST(:device AS string), '%')))")
    Page<UserSession> searchForAdmin(@Param("userId") Long userId,
                                      @Param("active") Boolean active,
                                      @Param("ipAddress") String ipAddress,
                                      @Param("device") String device,
                                      Pageable pageable);

    /** Backs TenantDataWipeService - this table has no clientApplicationId column, only userId. */
    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}
