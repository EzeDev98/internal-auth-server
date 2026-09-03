package com.internal.auth.feature.audit.service;

import com.internal.auth.feature.identity.model.User;

/**
 * Step 14A - the facade every business service calls to record an
 * auditable action. Deliberately doesn't expose "write an AuditLog row"
 * directly: record*() methods publish a domain event instead (see
 * AuditServiceImpl), and AuditEventListener is the only thing that ever
 * writes to AuditLogRepository. Callers of this interface don't need to
 * know that - the split exists so an audited action survives a crash
 * between the business transaction committing and the audit row actually
 * being written (Spring Modulith's JDBC event publication registry
 * replays the event on the next boot instead of silently losing it) without
 * every caller having to change.
 */
public interface AuditService {
    void recordUserLoggedIn(User user, Long clientApplicationId);
}
