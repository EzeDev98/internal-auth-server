package com.internal.auth.testsupport.builder;

import com.internal.auth.feature.rbac.model.Role;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Roles are intentionally global across tenants in this app (a deliberate
 * product decision - see Step 14C of the test roadmap), so this builder
 * takes no clientApplicationId - Role#clientApplication exists on the
 * entity but is unused by any current service or controller.
 */
public class RoleTestDataBuilder {

    private static final AtomicLong COUNTER = new AtomicLong();

    private String roleName;
    private String description = "Created by RoleTestDataBuilder";

    private RoleTestDataBuilder() {
        this.roleName = "test_role_" + COUNTER.incrementAndGet();
    }

    public static RoleTestDataBuilder aRole() {
        return new RoleTestDataBuilder();
    }

    /** The literal "create-admin" role - see AppConstant.ADMIN_ROLE / Roles.HAS_ADMIN. */
    public static RoleTestDataBuilder theAdminRole() {
        return new RoleTestDataBuilder()
                .withRoleName("create-admin")
                .withDescription("Full administrative access");
    }

    public RoleTestDataBuilder withRoleName(String roleName) {
        this.roleName = roleName;
        return this;
    }

    public RoleTestDataBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public Role build() {
        Role role = new Role();
        role.setRoleName(roleName);
        role.setDescription(description);
        role.setCreatedAt(LocalDateTime.now());
        return role;
    }
}
