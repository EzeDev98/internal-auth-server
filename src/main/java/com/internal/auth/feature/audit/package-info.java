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
 * Only the {@code service} sub-package is exposed as a named interface
 * (see its own package-info.java) - that's AuditService, the intentional
 * facade documented on that interface itself. Everything else here
 * (repository, model, event, enums, listener) stays internal to the
 * module; nothing outside this package should ever construct an AuditLog,
 * publish a UserLoggedInEvent directly, or call AuditLogRepository - see
 * AuditService's Javadoc for why that split exists.
 */
@org.springframework.modulith.ApplicationModule
package com.internal.auth.feature.audit;
