/**
 * Fix 3d (Spring Modulith boundary violations, see fix3modulithboundaries.md).
 *
 * {@code common} is a shared kernel - it exists specifically to be reused
 * by every other module ({@code config}, {@code feature}, and
 * {@code feature}'s own sub-packages like {@code feature.identity},
 * {@code feature.rbac}, etc.). Without this annotation, Modulith's default
 * direct-sub-package detection still treats {@code common} as a module, but
 * one whose own sub-packages ({@code common.exception}, {@code common.response},
 * {@code common.util}, {@code common.reset}, {@code common.crypto},
 * {@code common.email}, {@code common.constant}...) are internal by
 * default - invisible to every other module unless individually exposed.
 * That's backwards for a package whose entire purpose is to be depended on,
 * and it's what produced the large majority of
 * "Module '...' depends on non-exposed type ... within module 'common'"
 * violations against {@code ApplicationModules.verify()}.
 *
 * {@code ApplicationModule.Type.OPEN} tells Modulith that every sub-package
 * under {@code common} is part of its public API, so any other module can
 * depend on any type in it - exactly the intended role of a shared/base
 * module, and the officially documented pattern for one (as opposed to
 * marking everything OPEN globally as an escape hatch).
 *
 * This only clears the "common has internals other modules can't see"
 * violations. It does not address the genuine reverse dependency where
 * common.reset reaches into feature.passwordreset (fix 3a), the config ->
 * feature layering (fix 3c), or the feature <-> feature.audit cycle
 * (fix 3b) - those are separate, unrelated root causes tracked in the same
 * plan doc.
 */
@org.springframework.modulith.ApplicationModule(type = org.springframework.modulith.ApplicationModule.Type.OPEN)
package com.internal.auth.common;
