package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

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
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByEmail(String email);

    Optional<User> findByUsernameAndClientApplicationId(String username, Long clientApplicationId);
    Optional<User> findByPhoneNumberAndClientApplicationId(String phoneNumber, Long clientApplicationId);
    Optional<User> findByEmailAndClientApplicationId(String email, Long clientApplicationId);
}
