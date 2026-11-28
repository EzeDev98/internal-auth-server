package com.internal.auth.feature.admin.client;

/** Thrown when a downstream app's wipe call fails. */
public class DownstreamWipeException extends RuntimeException {
    public DownstreamWipeException(String message) {
        super(message);
    }
}
