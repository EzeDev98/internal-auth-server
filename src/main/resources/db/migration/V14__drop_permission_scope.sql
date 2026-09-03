-- Step 13F: remove PermissionScope (scopeType/scopeValue).
--
-- Confirmed dead code before removal, not just per the roadmap's original
-- note: PermissionScopesRepository is an empty JpaRepository marker with
-- no custom query methods, nothing in any service or controller
-- constructs/reads/writes a PermissionScope, and permission_scope has 0
-- rows. Step 13B already solved the real client-scoping need with a
-- direct FK on Role/PermissionGroup - PermissionScope's generic
-- scope-type/scope-value design was never built on top of and nothing
-- depends on it. Safe DROP TABLE, no data to preserve.

DROP TABLE permission_scope;
