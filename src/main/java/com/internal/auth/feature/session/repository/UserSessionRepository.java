package com.internal.auth.feature.session.repository;

import com.internal.auth.feature.session.model.UserSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/** Repository for user sessions. */
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByTokenHash(String tokenHash);
    List<UserSession> findAllByUserIdAndIsActiveTrue(Long userId);

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

    long deleteAllByUserIdIn(java.util.List<Long> userIds);
}
