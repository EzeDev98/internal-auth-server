package com.internal.auth.feature.audit.repository;

import com.internal.auth.feature.audit.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

/** Repository for audit log entries. */
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    long deleteAllByClientApplicationId(Long clientApplicationId);
}
