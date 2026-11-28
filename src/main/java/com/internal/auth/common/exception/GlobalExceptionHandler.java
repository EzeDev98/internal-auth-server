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

/** Maps every application exception to a uniform InternalAuthApiResponse. */
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

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<InternalAuthApiResponse<Void>> handleNoResourceFound(NoResourceFoundException ex) {
        HttpStatusCode status = ex.getStatusCode();
        String message = ex.getBody().getDetail();
        if (message == null || message.isBlank()) {
            message = "The requested resource could not be found.";
        }
        return ResponseEntity.status(status).body(InternalAuthApiResponse.<Void>error(message));
    }

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
