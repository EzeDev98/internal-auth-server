package com.internal.auth.feature.session.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.feature.session.dto.LogoutResponse;
import com.internal.auth.feature.session.service.LogoutService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("${app.title}")
@Tag(name = "Logout API", description = "Resource for terminating a user's authenticated session")
public class LogoutControl {

    private final LogoutService logoutService;

    @DeleteMapping("/session")
    public ResponseEntity<InternalAuthApiResponse<LogoutResponse>> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "").trim();
        LogoutResponse response = logoutService.logout(token);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }
}
