/**
 * The audit module's one named interface - see AuditService's own Javadoc
 * for why business services call this facade instead of touching
 * AuditLogRepository or publishing audit events directly. Marking this
 * package (rather than the whole module) as the named interface is what
 * lets LoginServiceImpl depend on AuditService without the module-boundary
 * verification in AuditEventListenerModuleTest treating that as reaching
 * into an internal package.
 */
@org.springframework.modulith.NamedInterface
package com.internal.auth.feature.audit.service;
