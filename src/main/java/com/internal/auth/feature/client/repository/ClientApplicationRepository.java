package com.internal.auth.feature.client.repository;

import com.internal.auth.feature.client.model.ClientApplication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/** Repository for client applications. */
@org.springframework.modulith.NamedInterface
public interface ClientApplicationRepository extends JpaRepository<ClientApplication, Long> {
    Optional<ClientApplication> findByClientId(String clientId);

    @Query("SELECT c FROM ClientApplication c WHERE " +
            "(:enabled IS NULL OR c.enabled = :enabled) AND " +
            "(:publicOnly IS NULL OR " +
            "(:publicOnly = TRUE AND c.clientSecretHash IS NULL) OR " +
            "(:publicOnly = FALSE AND c.clientSecretHash IS NOT NULL))")
    Page<ClientApplication> searchForAdmin(@Param("enabled") Boolean enabled,
                                            @Param("publicOnly") Boolean publicOnly,
                                            Pageable pageable);
}
