package com.internal.auth.config.auth;

public final class Roles {

    private Roles() {}

    public static final String HAS_ADMIN = "hasRole('create-admin')";

    public static final String HAS_USER = "hasRole('basic_access')";

    public static final String HAS_SERVICE = "hasRole('service')";

    public static final String HAS_USER_OR_SERVICE = "hasAnyRole('basic_access', 'service')";

    public static final String HAS_ADMIN_OR_SERVICE = "hasAnyRole('create-admin', 'service')";

    public static final String HAS_ADMIN_OR_USER = "hasAnyRole('create-admin', 'basic_access')";
}