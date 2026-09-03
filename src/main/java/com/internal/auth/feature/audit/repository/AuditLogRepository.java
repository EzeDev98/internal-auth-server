package com.internal.auth.feature.audit.repository;

import com.internal.auth.feature.audit.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}
