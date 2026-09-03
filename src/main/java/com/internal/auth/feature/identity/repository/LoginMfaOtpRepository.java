package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.identity.model.LoginMfaOtp;
import com.internal.auth.feature.passwordreset.enums.PasswordResetStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LoginMfaOtpRepository extends JpaRepository<LoginMfaOtp, Long> {
    Optional<LoginMfaOtp> findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(String phoneNumber, PasswordResetStatus status);
}
