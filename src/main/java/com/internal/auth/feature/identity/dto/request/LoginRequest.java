package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for POST /api/v1/auth/login (Step 11A). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    private String username;
    private String password;

    /**
     * Step 17h (B-14): the person's own browser User-Agent, for a client that signs people in from its
     * own server (Notare). Without it the session would be labelled with that server's HTTP client.
     * Optional: when blank, the request's User-Agent header is used, as before.
     */
    private String userAgent;

    public LoginRequest(String username, String password) {
        this(username, password, null);
    }
}
