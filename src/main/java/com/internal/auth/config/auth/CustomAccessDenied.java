package com.internal.auth.config.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.response.InternalAuthApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/** Returns a uniform JSON response when access is denied. */
@Component
public class CustomAccessDenied implements AccessDeniedHandler {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        InternalAuthApiResponse<Void> body = InternalAuthApiResponse.<Void>builder()
                .success(false)
                .message("Access denied. You do not have permission to perform this action.")
                .build();

        MAPPER.writeValue(response.getWriter(), body);
    }
}
