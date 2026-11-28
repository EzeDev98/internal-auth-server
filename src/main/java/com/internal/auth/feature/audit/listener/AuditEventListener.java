package com.internal.auth.feature.audit.listener;

import com.internal.auth.feature.audit.enums.AuditAction;
import com.internal.auth.feature.audit.event.ClientSettingsChangedEvent;
import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.feature.audit.model.AuditLog;
import com.internal.auth.feature.audit.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/** Writes audit log entries in response to published events. */
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

    @ApplicationModuleListener
    void on(ClientSettingsChangedEvent event) {
        AuditLog auditLog = new AuditLog();
        auditLog.setActorUsername(event.getActorUsername());
        auditLog.setClientApplicationId(event.getClientApplicationId());
        auditLog.setAction(AuditAction.CLIENT_SESSION_SETTINGS_CHANGED.name());
        auditLog.setDescription(event.getDescription());
        auditLogRepository.save(auditLog);
    }
}
