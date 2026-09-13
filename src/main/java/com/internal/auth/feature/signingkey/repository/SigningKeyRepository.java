package com.internal.auth.feature.signingkey.repository;

import com.internal.auth.feature.signingkey.enums.SigningKeyStatus;
import com.internal.auth.feature.signingkey.model.SigningKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface SigningKeyRepository extends JpaRepository<SigningKey, Long> {

    List<SigningKey> findByStatus(SigningKeyStatus status);

    Optional<SigningKey> findByCurrentTrue();

    List<SigningKey> findByStatusAndCurrentFalseAndCreatedAtBefore(SigningKeyStatus status, LocalDateTime cutoff);

    List<SigningKey> findAllByOrderByCreatedAtDesc();
}
