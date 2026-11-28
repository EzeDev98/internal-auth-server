package com.internal.auth.testsupport.builder;

import com.internal.auth.feature.rbac.model.PermissionGroup;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicLong;

/** Test data builder for PermissionGroup. */
public class PermissionGroupTestDataBuilder {

    private static final AtomicLong COUNTER = new AtomicLong();

    private String groupName;
    private String description = "Created by PermissionGroupTestDataBuilder";

    private PermissionGroupTestDataBuilder() {
        this.groupName = "test_group_" + COUNTER.incrementAndGet();
    }

    public static PermissionGroupTestDataBuilder aPermissionGroup() {
        return new PermissionGroupTestDataBuilder();
    }

    public PermissionGroupTestDataBuilder withGroupName(String groupName) {
        this.groupName = groupName;
        return this;
    }

    public PermissionGroupTestDataBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public PermissionGroup build() {
        PermissionGroup group = new PermissionGroup();
        group.setGroupName(groupName);
        group.setDescription(description);
        group.setCreatedAt(LocalDateTime.now());
        return group;
    }
}
