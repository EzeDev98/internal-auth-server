package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.ActivationRequest;
import com.internal.auth.feature.identity.dto.response.ActivationResponse;
import com.internal.auth.feature.identity.dto.request.ResendActivationRequest;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.internal.auth.common.response.InternalAuthApiResponse;

/** Endpoints for account activation by email. */
@RestController
@RequestMapping("${app.title}/auth")
@Tag(name = "Email Verification API", description = "Account activation via emailed link")
@RequiredArgsConstructor
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;
    private final ClientApplicationService clientApplicationService;

    @GetMapping("/activate")
    public ResponseEntity<InternalAuthApiResponse<Void>> activateViaLink(@RequestParam String token) {
        ActivationResponse response = emailVerificationService.activate(token);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage()));
    }

    @PostMapping("/activate")
    public ResponseEntity<InternalAuthApiResponse<Void>> activateViaApi(@RequestBody ActivationRequest request) {
        ActivationResponse response = emailVerificationService.activate(request.getToken());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage()));
    }

    @PostMapping("/resend-activation")
    public ResponseEntity<InternalAuthApiResponse<Void>> resendActivation(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody ResendActivationRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        ActivationResponse response = emailVerificationService.resendVerification(request.getEmail(), client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage()));
    }
}
