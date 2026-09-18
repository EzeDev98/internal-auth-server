package com.internal.auth.feature.admin.client;

/**
 * Thrown by {@link DownstreamAppWipeClient} when a call to SyncPoint's or
 * Notare's own wipe endpoint fails - bad/missing secret on either side,
 * a rejected confirmation, the app being unreachable, or a 5xx from its
 * own wipe logic. Always caught by WipeAllService, which turns it into a
 * WipeAllResponse.Step(success=false, message=...) rather than letting it
 * reach GlobalExceptionHandler - see WipeAllService's class Javadoc for
 * why the whole operation stops there instead of continuing.
 */
public class DownstreamWipeException extends RuntimeException {
    public DownstreamWipeException(String message) {
        super(message);
    }
}
