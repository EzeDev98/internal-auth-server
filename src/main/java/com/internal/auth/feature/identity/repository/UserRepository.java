package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Moved from feature.rbac.repository as part of Stage 2 punch-list item 1
 * (User entity redesign/relocation). findByEmail added for Step 10A
 * (registration) - needed to check email-uniqueness the same way
 * findByPhoneNumber already lets registration check phone-uniqueness.
 */
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByEmail(String email);
}
