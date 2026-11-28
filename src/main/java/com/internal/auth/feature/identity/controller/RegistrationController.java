package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.RegisterRequest;
import com.internal.auth.feature.identity.dto.response.RegisterResponse;
import com.internal.auth.feature.identity.service.UserRegistrationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.internal.auth.common.response.InternalAuthApiResponse;

/** Endpoint for user registration. */
@RestController
@RequestMapping("${app.title}/auth")
@Tag(name = "Registration API", description = "Account creation")
@RequiredArgsConstructor
public class RegistrationController {

    private final UserRegistrationService registrationService;
    private final ClientApplicationService clientApplicationService;

    @PostMapping("/register")
    public ResponseEntity<InternalAuthApiResponse<RegisterResponse>> register(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody RegisterRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        RegisterResponse response = registrationService.register(request, client.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(InternalAuthApiResponse.success(response.getMessage(), response));
    }
}
