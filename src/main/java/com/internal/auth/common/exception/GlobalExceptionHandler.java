package com.internal.auth.common.exception;

import com.internal.auth.common.response.InternalAuthApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Stage 1 punch-list item 7: a single place that turns every exception this
 * app can throw into the same {@link InternalAuthApiResponse} JSON shape
 * CustomAccessDenied/CustomAuthenticationEntryPoint already use for 403/401
 * responses — instead of Spring Boot's default whitelabel/BasicErrorController
 * body leaking through for everything else. That default body also omits the
 * exception message unless server.error.include-message=always is set (it
 * isn't, anywhere in this app), so today every one of the ~30 custom
 * exceptions in this package loses its carefully written, client-safe
 * message before it ever reaches a caller. This restores it.
 *
 * <p><b>Why AccessDeniedException / AuthenticationException are handled
 * here too, instead of left alone:</b> {@code @RestControllerAdvice}
 * handlers run inside DispatcherServlet, via ExceptionHandlerExceptionResolver
 * — which gets first look at any exception thrown from a controller method,
 * before it would ever reach ExceptionTranslationFilter further out in the
 * servlet filter chain (where CustomAccessDenied / CustomAuthenticationEntryPoint
 * are wired, see WebSecurityConfig). Without an explicit, equally-specific
 * handler for these two types here, the broad {@code RuntimeException}
 * catch-all below would intercept them first — both from {@code @PreAuthorize}
 * denials and from manual throws like
 * {@code AuthenticationHelper.requireSelfOrAdmin} (used by the item-3 IDOR
 * fix and the item-5 session-invalidate fix) — and silently downgrade their
 * correct 403/401 into this class's generic 500 fallback. The handlers below
 * intentionally return the exact same status/message
 * CustomAccessDenied/CustomAuthenticationEntryPoint already return, so the
 * response is identical no matter which layer ends up resolving it.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleAccessDenied(AccessDeniedException ex) {
        return build(HttpStatus.FORBIDDEN, "Access denied. You do not have permission to perform this action.", null);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleAuthenticationException(AuthenticationException ex) {
        return build(HttpStatus.UNAUTHORIZED, "Authentication required. Please provide a valid token.", null);
    }

    @ExceptionHandler(PermissionException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handlePermissionException(PermissionException ex) {
        log.warn("PermissionException [{}]: {}", ex.getErrorCode(), ex.getMessage());
        return build(ex.getStatus(), ex.getMessage(), String.valueOf(ex.getErrorCode().getCode()));
    }

    @ExceptionHandler(OtpResendCooldownException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleOtpResendCooldown(OtpResendCooldownException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()))
                .body(InternalAuthApiResponse.<Void>error(ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleMalformedBody(HttpMessageNotReadableException ex) {
        return build(HttpStatus.BAD_REQUEST, "Malformed or missing request body", null);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleMissingParam(MissingServletRequestParameterException ex) {
        return build(HttpStatus.BAD_REQUEST, ex.getMessage(), null);
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleInvalidRefreshTokenException(InvalidRefreshTokenException ex) {
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), null);
    }

    /**
     * Catches NoResourceFoundException - thrown for literally any request
     * whose path matches no controller mapping. Ground-truthed via javap
     * against spring-webmvc 7.0.9
     * (org.springframework.web.servlet.resource.NoResourceFoundException):
     * it extends jakarta.servlet.ServletException - a CHECKED exception, so
     * it can never reach handleRuntimeException below, which only catches
     * RuntimeException - and separately implements
     * org.springframework.web.ErrorResponse, which is what makes
     * getStatusCode()/getBody() available here even though it isn't itself
     * a RuntimeException. Without this handler it falls through everything
     * to handleUnexpected, turning "no such endpoint" into a misleading 500
     * for every unmapped URL this app has ever received.
     *
     * History: an earlier version of this handler targeted
     * ErrorResponseException instead, on the unverified assumption that
     * NoResourceFoundException extended it. It doesn't - the javap output
     * above is the ground truth - so that handler never matched and this
     * bug wasn't actually fixed until now.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleNoResourceFound(NoResourceFoundException ex) {
        HttpStatusCode status = ex.getStatusCode();
        String message = ex.getBody().getDetail();
        if (message == null || message.isBlank()) {
            message = "The requested resource could not be found.";
        }
        return ResponseEntity.status(status).body(InternalAuthApiResponse.<Void>error(message));
    }

    /**
     * Catches every other exception this app throws that's annotated with
     * {@code @ResponseStatus} — BadRequestException, OtpExpiredException,
     * OtpInvalidException, MaxAttemptsExceededException,
     * ResetTokenInvalidException, UserNotFoundException,
     * InternalServerErrorException, and any future one — by reading the
     * status directly off the annotation, so a new {@code @ResponseStatus}
     * exception class never needs a new handler added here. Anything that
     * reaches this method WITHOUT that annotation is a genuinely unexpected
     * error (a bug, not a modeled business exception) and falls through to
     * {@link #handleUnexpected}.
     */
    /**
     * Step 19C: catches any DataAccessException that escapes uncaught from
     * anywhere in the app - connection pool exhaustion,
     * CannotCreateTransactionException when Postgres itself is unreachable,
     * query timeouts, etc. Every DataAccessException this codebase
     * "expects" (DataIntegrityViolationException for uniqueness conflicts,
     * and the rest) is already caught and converted to a specific typed
     * exception inside the relevant service method, so this handler only
     * ever sees genuine infrastructure failures - a chaos test that kills
     * the database mid-traffic is exactly what exercises this path.
     * Without it, an outage previously surfaced as a misleading 500
     * ("something is broken in your request") instead of a 503
     * ("the service itself is temporarily down").
     */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleDataAccessException(DataAccessException ex) {
        log.error("Database connectivity failure", ex);
        return build(HttpStatus.SERVICE_UNAVAILABLE, "The service is temporarily unavailable. Please try again shortly.", null);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleRuntimeException(RuntimeException ex) {
        ResponseStatus responseStatus = AnnotatedElementUtils.findMergedAnnotation(ex.getClass(), ResponseStatus.class);
        if (responseStatus != null) {
            log.warn("{}: {}", ex.getClass().getSimpleName(), ex.getMessage());
            return build(responseStatus.value(), ex.getMessage(), null);
        }
        return handleUnexpected(ex);
    }

    /**
     * Final backstop for anything not covered above — including checked
     * exceptions, which {@link #handleRuntimeException} can't catch. Never
     * leaks the raw exception message (it wasn't written with an API caller
     * in mind, unlike this app's modeled exceptions); full details go to the
     * server log only.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleUnexpected(Exception ex) {
        log.error("Unhandled exception", ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.", null);
    }

    private ResponseEntity<InternalAuthApiResponse<Void>> build(HttpStatus status, String message, String errorCode) {
        InternalAuthApiResponse<Void> body = errorCode != null
                ? InternalAuthApiResponse.<Void>error(message, errorCode)
                : InternalAuthApiResponse.<Void>error(message);
        return ResponseEntity.status(status).body(body);
    }
}
