package com.internal.auth.feature.session.repository;

import com.internal.auth.feature.session.model.UserSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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

    /**
     * Step 2E (React Admin Client plan v4): backs GET
     * ${app.title}/admin/sessions - the admin session directory's
     * list/filter. Every filter is nullable to mean "don't filter on
     * this"; ipAddress/device match as a case-insensitive substring.
     */
    @Query("SELECT s FROM UserSession s WHERE " +
            "(:userId IS NULL OR s.userId = :userId) AND " +
            "(:active IS NULL OR s.isActive = :active) AND " +
            "(:ipAddress IS NULL OR LOWER(s.ipAddress) LIKE LOWER(CONCAT('%', :ipAddress, '%'))) AND " +
            "(:device IS NULL OR LOWER(s.userAgent) LIKE LOWER(CONCAT('%', :device, '%')))")
    Page<UserSession> searchForAdmin(@Param("userId") Long userId,
                                      @Param("active") Boolean active,
                                      @Param("ipAddress") String ipAddress,
                                      @Param("device") String device,
                                      Pageable pageable);

    /** Backs TenantDataWipeService - this table has no clientApplicationId column, only userId. */
    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}
