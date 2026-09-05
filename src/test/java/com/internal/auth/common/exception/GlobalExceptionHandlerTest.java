package com.internal.auth.common.exception;

import com.internal.auth.common.response.InternalAuthApiResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Step 5A/D - one test per {@code @ExceptionHandler} method on
 * GlobalExceptionHandler. The class has no injected dependencies, so every
 * handler method is called directly rather than through a Spring context -
 * this is a plain unit test, not a @WebMvcTest.
 */
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void accessDenied_mapsTo403WithFixedMessage() {
        ResponseEntity<InternalAuthApiResponse<Void>> response =
                handler.handleAccessDenied(new AccessDeniedException("denied"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        InternalAuthApiResponse<Void> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.isSuccess()).isFalse();
        assertThat(body.getMessage()).isEqualTo("Access denied. You do not have permission to perform this action.");
    }

    @Test
    void authenticationException_mapsTo401WithFixedMessage() {
        ResponseEntity<InternalAuthApiResponse<Void>> response =
                handler.handleAuthenticationException(new BadCredentialsException("bad creds"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().getMessage())
                .isEqualTo("Authentication required. Please provide a valid token.");
    }

    @Test
    void permissionException_usesItsOwnStatusMessageAndErrorCode() {
        PermissionException ex = PermissionException.roleNotFound("Role 'BUYER' not found");

        ResponseEntity<InternalAuthApiResponse<Void>> response = handler.handlePermissionException(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        InternalAuthApiResponse<Void> body = response.getBody();
        assertThat(body.getMessage()).isEqualTo("Role 'BUYER' not found");
        assertThat(body.getErrorCode()).isEqualTo(String.valueOf(PermissionErrorCode.ROLE_NOT_FOUND.getCode()));
    }

    @Test
    void otpResendCooldown_returns429WithRetryAfterHeaderAndMessage() {
        OtpResendCooldownException ex =
                new OtpResendCooldownException("Please wait before requesting another code", 30L);

        ResponseEntity<InternalAuthApiResponse<Void>> response = handler.handleOtpResendCooldown(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(response.getBody().getMessage()).isEqualTo("Please wait before requesting another code");
    }

    @Test
    void malformedBody_mapsTo400WithFixedMessage() {
        HttpMessageNotReadableException ex = mock(HttpMessageNotReadableException.class);

        ResponseEntity<InternalAuthApiResponse<Void>> response = handler.handleMalformedBody(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getMessage()).isEqualTo("Malformed or missing request body");
    }

    @Test
    void missingRequestParameter_mapsTo400WithTheExceptionsOwnMessage() {
        MissingServletRequestParameterException ex = mock(MissingServletRequestParameterException.class);
        when(ex.getMessage()).thenReturn("Required request parameter 'username' is not present");

        ResponseEntity<InternalAuthApiResponse<Void>> response = handler.handleMissingParam(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getMessage()).isEqualTo("Required request parameter 'username' is not present");
    }

    @Test
    void noResourceFound_usesTheExceptionsOwnStatusAndDetail() {
        NoResourceFoundException ex = mock(NoResourceFoundException.class);
        when(ex.getStatusCode()).thenReturn(HttpStatus.NOT_FOUND);
        when(ex.getBody()).thenReturn(ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "No handler for /nope"));

        ResponseEntity<InternalAuthApiResponse<Void>> response = handler.handleNoResourceFound(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody().getMessage()).isEqualTo("No handler for /nope");
    }

    @Test
    void noResourceFound_blankDetailFallsBackToDefaultMessage() {
        NoResourceFoundException ex = mock(NoResourceFoundException.class);
        when(ex.getStatusCode()).thenReturn(HttpStatus.NOT_FOUND);
        when(ex.getBody()).thenReturn(ProblemDetail.forStatus(HttpStatus.NOT_FOUND));

        ResponseEntity<InternalAuthApiResponse<Void>> response = handler.handleNoResourceFound(ex);

        assertThat(response.getBody().getMessage()).isEqualTo("The requested resource could not be found.");
    }

    @Test
    void runtimeException_withResponseStatusAnnotation_usesAnnotatedStatus() {
        ResponseEntity<InternalAuthApiResponse<Void>> response =
                handler.handleRuntimeException(new BadRequestException("bad input"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getMessage()).isEqualTo("bad input");
    }

    @Test
    void runtimeException_withoutResponseStatusAnnotation_fallsBackToUnexpected() {
        ResponseEntity<InternalAuthApiResponse<Void>> response =
                handler.handleRuntimeException(new IllegalStateException("some internal detail"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getMessage())
                .isEqualTo("An unexpected error occurred. Please try again later.")
                .doesNotContain("some internal detail");
    }

    @Test
    void unexpected_neverLeaksTheRawExceptionMessage() {
        ResponseEntity<InternalAuthApiResponse<Void>> response =
                handler.handleUnexpected(new Exception("stack-trace-worthy internal detail"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getMessage())
                .isEqualTo("An unexpected error occurred. Please try again later.");
    }
}
