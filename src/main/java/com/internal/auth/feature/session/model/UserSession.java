package com.internal.auth.feature.session.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** User session entity storing a hashed token. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "is_active", nullable = false)
    private boolean isActive;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "ended_at")
    private LocalDateTime endedAt;

    @Column(name = "end_reason", length = 50)
    private String endReason;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "device_label", length = 100)
    private String deviceLabel;

    @Column(name = "last_active_at")
    private LocalDateTime lastActiveAt;

    @Column(name = "authorization_id", length = 100)
    private String authorizationId;

}
