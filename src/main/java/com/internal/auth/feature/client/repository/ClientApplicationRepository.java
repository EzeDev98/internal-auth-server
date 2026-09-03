package com.internal.auth.feature.client.repository;

import com.internal.auth.feature.client.model.ClientApplication;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Stage 2 punch-list item 3. No service or controller layer exists yet -
 * this is here purely so the entity has somewhere to be persisted/queried
 * from once client registration and OAuth2 Authorization Server
 * integration are actually built (Stage 3/4).
 */
public interface ClientApplicationRepository extends JpaRepository<ClientApplication, Long> {
    Optional<ClientApplication> findByClientId(String clientId);
}
