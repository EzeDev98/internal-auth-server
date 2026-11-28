package com.internal.auth.config.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.response.InternalAuthApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/** Returns a uniform JSON response when authentication is missing or invalid. */
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        InternalAuthApiResponse<Void> body = InternalAuthApiResponse.<Void>builder()
                .success(false)
                .message("Authentication required. Please provide a valid token.")
                .build();

        MAPPER.writeValue(response.getWriter(), body);
    }
}
