package com.internal.auth.feature.client.repository;

import com.internal.auth.feature.client.model.ClientApplication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * Stage 2 punch-list item 3. No service or controller layer exists yet -
 * this is here purely so the entity has somewhere to be persisted/queried
 * from once client registration and OAuth2 Authorization Server
 * integration are actually built (Stage 3/4).
 */
@org.springframework.modulith.NamedInterface
public interface ClientApplicationRepository extends JpaRepository<ClientApplication, Long> {
    Optional<ClientApplication> findByClientId(String clientId);

    /**
     * Step 2B (React Admin Client plan v4): backs GET
     * ${app.title}/client-applications - the admin client-application
     * directory's list/filter. enabled is nullable to mean "don't filter on
     * this"; publicOnly is nullable the same way and checks
     * clientSecretHash's presence (there's no separate "type" column - see
     * ClientApplication's class Javadoc) - true matches public/no-secret
     * clients, false matches confidential/has-secret clients.
     */
    @Query("SELECT c FROM ClientApplication c WHERE " +
            "(:enabled IS NULL OR c.enabled = :enabled) AND " +
            "(:publicOnly IS NULL OR " +
            "(:publicOnly = TRUE AND c.clientSecretHash IS NULL) OR " +
            "(:publicOnly = FALSE AND c.clientSecretHash IS NOT NULL))")
    Page<ClientApplication> searchForAdmin(@Param("enabled") Boolean enabled,
                                            @Param("publicOnly") Boolean publicOnly,
                                            Pageable pageable);
}
