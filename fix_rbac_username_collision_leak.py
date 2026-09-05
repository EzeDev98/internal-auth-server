import sys

path = "src/main/java/com/internal/auth/feature/rbac/service/impl/EntityUtilityService.java"

old = '''    public List<PermissionGroup> findUserPermissionGroups(String username) {
        List<PermissionGroup> permissionGroups = userPermissionGroupRepository.findPermissionGroupsByUsername(username);
        if (CollectionUtils.isEmpty(permissionGroups)) {
            return Collections.emptyList();
        }
        return permissionGroups;
    }

    public List<Role> findUserRoles(String username) {

        List<Role> userRoles = userRolesRepository.findRolesByUsername(username);
        if (CollectionUtils.isEmpty(userRoles)) {
            return Collections.emptyList();
        }
        return userRoles;
    }'''

new = '''    /**
     * Step 14A fix: previously queried by bare username with no tenant
     * scoping (findPermissionGroupsByUsername), so a username colliding
     * across two client applications silently merged both users' group
     * memberships into one list. Now resolves through getUser(username)
     * first - the same fail-closed (409 AMBIGUOUS_USERNAME) guard every
     * other RBAC admin lookup already goes through - then looks up by
     * that single resolved user via the existing findAllByUser(User),
     * never joining on username directly.
     */
    public List<PermissionGroup> findUserPermissionGroups(String username) {
        User user = getUser(username);
        List<UserPermissionGroup> mappings = userPermissionGroupRepository.findAllByUser(user);
        if (CollectionUtils.isEmpty(mappings)) {
            return Collections.emptyList();
        }
        return mappings.stream()
                .map(UserPermissionGroup::getPermissionGroup)
                .distinct()
                .toList();
    }

    /**
     * Step 14A fix: same issue and same fix shape as
     * findUserPermissionGroups above - findRolesByUsername had no tenant
     * scoping either. Now resolves through getUser(username)'s
     * fail-closed guard, then reuses findRolesByUserId (already the
     * tenant-safe lookup LoginServiceImpl#mintAccessToken relies on for
     * JWT role claims - see its own Javadoc).
     */
    public List<Role> findUserRoles(String username) {
        User user = getUser(username);
        List<Role> userRoles = userRolesRepository.findRolesByUserId(user.getId());
        if (CollectionUtils.isEmpty(userRoles)) {
            return Collections.emptyList();
        }
        return userRoles;
    }'''

with open(path, "r") as f:
    content = f.read()

count = content.count(old)
if count != 1:
    print(f"ABORT: expected exactly 1 match for the anchor block, found {count}. No changes written.", file=sys.stderr)
    sys.exit(1)

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patched EntityUtilityService.java: findUserPermissionGroups/findUserRoles now resolve through the tenant-safe getUser() guard.")
