package com.internal.auth.feature.audit.listener;

import com.internal.auth.feature.audit.enums.AuditAction;
import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.feature.audit.model.AuditLog;
import com.internal.auth.feature.audit.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/**
 * Step 14A - the only thing that ever writes to AuditLogRepository. Runs
 * as an async, REQUIRES_NEW-transactional listener (that's what
 * {@code @ApplicationModuleListener} expands to - see its own Javadoc),
 * backed by Spring Modulith's JDBC event publication registry: if this app
 * crashes after the business transaction that published the event
 * committed but before this listener ran, the event is durably logged in
 * the event_publication table and gets replayed on the next boot instead
 * of silently lost. See this same step's pom.xml/application-*.properties
 * changes for how that registry is wired up (auto-schema-init in dev,
 * Flyway-managed V15 migration in prod).
 */
@Component
@RequiredArgsConstructor
public class AuditEventListener {

    private final AuditLogRepository auditLogRepository;

    @ApplicationModuleListener
    void on(UserLoggedInEvent event) {
        AuditLog auditLog = new AuditLog();
        auditLog.setActorUserId(event.getUserId());
        auditLog.setActorUsername(event.getUsername());
        auditLog.setClientApplicationId(event.getClientApplicationId());
        auditLog.setAction(AuditAction.LOGIN_SUCCESS.name());
        auditLogRepository.save(auditLog);
    }
}
