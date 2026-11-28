package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/** Repository for users. */
@org.springframework.modulith.NamedInterface
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByEmail(String email);
    Optional<User> findByInternalAuthUserIdAndClientApplicationId(String internalAuthUserId, Long clientApplicationId);

    Optional<User> findByInternalAuthUserId(String internalAuthUserId);

    List<User> findAllByUsername(String username);

    Optional<User> findByUsernameAndClientApplicationId(String username, Long clientApplicationId);
    Optional<User> findByPhoneNumberAndClientApplicationId(String phoneNumber, Long clientApplicationId);
    Optional<User> findByEmailAndClientApplicationId(String email, Long clientApplicationId);

    @Query("SELECT u FROM User u WHERE " +
            "(:clientApplicationId IS NULL OR u.clientApplicationId = :clientApplicationId) AND " +
            "(:enabled IS NULL OR u.enabled = :enabled) AND " +
            "(:search IS NULL OR " +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', CAST(:search AS string), '%')) OR " +
            "LOWER(u.phoneNumber) LIKE LOWER(CONCAT('%', CAST(:search AS string), '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', CAST(:search AS string), '%')))")
    Page<User> searchForAdmin(@Param("clientApplicationId") Long clientApplicationId,
                               @Param("enabled") Boolean enabled,
                               @Param("search") String search,
                               Pageable pageable);

    List<User> findAllByClientApplicationId(Long clientApplicationId);

    long deleteAllByClientApplicationId(Long clientApplicationId);
}
