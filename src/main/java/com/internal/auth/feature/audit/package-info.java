/**
 * Spring Modulith application module for the audit trail.
 *
 * Explicitly annotated rather than left to the default direct-sub-package
 * detection strategy - under that default, everything under `feature`
 * (identity, rbac, session, signingkey, client, passwordreset, audit...)
 * collapses into one single "feature" module, too coarse for the isolated
 * {@code @ApplicationModuleTest} added in Step 17A. Explicit annotation
 * plus {@code spring.modulith.detection-strategy=explicitly-annotated}
 * (set only in application-test.properties, so this doesn't change how
 * dev/prod boot at all) carves "audit" out on its own without requiring
 * every other feature package to be annotated in the same change - those
 * stay unmoduled ("free") code for now; giving them the same treatment is
 * a separate, larger effort.
 *
 * Only the {@code event} sub-package is exposed as a named interface (see
 * its own package-info.java, fix 3b of fix3modulithboundaries.md) - business
 * services publish {@code UserLoggedInEvent} directly via the standard
 * {@code ApplicationEventPublisher} bean. There used to be a {@code service}
 * facade (AuditService) wrapping that publish call, but its
 * recordUserLoggedIn(User, Long) method took feature.identity's User
 * entity as a parameter, which made this module depend back on feature -
 * a real cycle against ApplicationModules.verify(). Removed rather than
 * fixed in place, since the facade added no behavior beyond the publish
 * call it wrapped. Everything else here (repository, model, enums,
 * listener) stays internal to the module; nothing outside this package
 * should ever construct an AuditLog or call AuditLogRepository directly -
 * see AuditEventListener's Javadoc for why it's the sole writer.
 */
@org.springframework.modulith.ApplicationModule
package com.internal.auth.feature.audit;
