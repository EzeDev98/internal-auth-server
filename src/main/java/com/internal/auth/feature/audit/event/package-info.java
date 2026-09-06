/**
 * Fix 3b (Spring Modulith boundary violations, see fix3modulithboundaries.md).
 *
 * The audit module's one named interface. Previously {@code service}
 * (AuditService) held this role: business services called that facade,
 * which published {@link com.internal.auth.feature.audit.event.UserLoggedInEvent}
 * on their behalf. That indirection existed only to keep callers from
 * publishing the event directly - but AuditService.recordUserLoggedIn(User,
 * Long) took the feature.identity {@code User} entity as a parameter,
 * which made {@code feature.audit} depend back on {@code feature.identity}
 * and produced a real "Slice feature -> Slice feature.audit -> Slice
 * feature" cycle against {@code ApplicationModules.verify()} (LoginServiceImpl
 * depended on AuditService; AuditService/AuditServiceImpl depended on User).
 *
 * AuditService and AuditServiceImpl are gone - callers now publish
 * {@code UserLoggedInEvent} directly via the standard
 * {@code ApplicationEventPublisher} bean, carrying only primitives (userId,
 * username, clientApplicationId), never the User entity itself. That
 * removes the reverse dependency entirely rather than papering over it,
 * and this package - not {@code service} - is what has to be exposed for
 * it. {@code AuditEventListener} (see its own Javadoc) is still, and has
 * always been, the only thing that ever writes to AuditLogRepository.
 */
@org.springframework.modulith.NamedInterface
package com.internal.auth.feature.audit.event;
