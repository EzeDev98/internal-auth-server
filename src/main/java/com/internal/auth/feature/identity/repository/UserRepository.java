package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/**
 * Moved from feature.rbac.repository as part of Stage 2 punch-list item 1
 * (User entity redesign/relocation). findByEmail added for Step 10A
 * (registration) - needed to check email-uniqueness the same way
 * findByPhoneNumber already lets registration check phone-uniqueness.
 *
 * Multi-tenant redesign, schema/model step (see User's class Javadoc and
 * the V8 migration): findByUsername/findByPhoneNumber/findByEmail below
 * are UNSCOPED and become unsafe (IncorrectResultSizeDataAccessException,
 * or an arbitrary match) the moment two different client applications have
 * a user sharing the same username/phone/email - now possible now that
 * uniqueness is enforced per client_application_id, not globally. Kept
 * temporarily because RegistrationServiceImpl/LoginServiceImpl still call
 * them and haven't been migrated to the *AndClientApplicationId variants
 * below yet - that's the next step, at which point these three should be
 * deleted rather than left as dead, dangerous code.
 */
@org.springframework.modulith.NamedInterface
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByEmail(String email);
    Optional<User> findByInternalAuthUserIdAndClientApplicationId(String internalAuthUserId, Long clientApplicationId);

    // internalAuthUserId is globally unique (generated once at
    // registration, never reused), unlike username/phone/email - so this
    // bare lookup is safe without a clientApplicationId qualifier. Backs
    // jwtTokenCustomizer, which only has the JWT's own principal name to
    // key off (see AuthorizationServerConfig's javadoc on that bean).
    Optional<User> findByInternalAuthUserId(String internalAuthUserId);

    /**
     * Step 2 (RBAC admin lookup fix): unscoped by client_application_id like
     * findByUsername above, but returns every match instead of assuming
     * exactly one - lets a caller detect "this username exists in more than
     * one tenant" explicitly (see EntityUtilityService#getUser) instead of
     * an opaque IncorrectResultSizeDataAccessException or silently favouring
     * whichever row the DB happens to return first.
     */
    List<User> findAllByUsername(String username);

    Optional<User> findByUsernameAndClientApplicationId(String username, Long clientApplicationId);
    Optional<User> findByPhoneNumberAndClientApplicationId(String phoneNumber, Long clientApplicationId);
    Optional<User> findByEmailAndClientApplicationId(String email, Long clientApplicationId);

    /**
     * Step 2A (React Admin Client plan v4): backs GET ${app.title}/users -
     * the admin user directory's list/search. clientApplicationId is
     * nullable on purpose (pass null to list across every tenant); enabled
     * is nullable to mean "don't filter on this"; search is nullable/blank
     * to mean "no text filter", otherwise matched case-insensitively as a
     * substring against username, phoneNumber, and email.
     */
    // CAST(:search AS string) below is not decorative - without it, Postgres
    // has to infer a type for :search purely from its position inside
    // CONCAT(...)/LOWER(...), since it's never compared directly against a
    // typed column. Hibernate 7 + pgjdbc infers that as bytea instead of
    // text in this shape, and Postgres's lower() has no bytea overload,
    // so every search-filtered call to this query fails with
    // "function lower(bytea) does not exist" - confirmed via
    // information_schema (username/phone_number/email are all plain
    // character varying; this was never a real schema issue). The
    // explicit cast removes the ambiguity Postgres was guessing at.
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

    /** Backs TenantDataWipeService - every user in one tenant, so their ids can be collected before cascading deletes. */
    List<User> findAllByClientApplicationId(Long clientApplicationId);

    /** Backs TenantDataWipeService - deletes the users themselves once every child table is cleared. */
    long deleteAllByClientApplicationId(Long clientApplicationId);
}
