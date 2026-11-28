package com.internal.auth.config.auth;

/** Role expressions used in method-level security annotations. */
public final class Roles {

    private Roles() {}

    public static final String HAS_ADMIN = "hasRole('create-admin')";

    public static final String HAS_USER = "hasRole('basic_access')";

    public static final String HAS_SERVICE = "hasRole('service')";

    public static final String HAS_ADMIN_OR_SERVICE = "hasAnyRole('create-admin', 'service')";

    public static final String HAS_ADMIN_OR_USER = "hasAnyRole('create-admin', 'basic_access')";
}
