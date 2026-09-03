package com.internal.auth.feature.passwordreset.repository;

import com.internal.auth.feature.passwordreset.enums.PasswordResetStatus;
import com.internal.auth.feature.passwordreset.model.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {
    Optional<PasswordResetOtp> findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(String phoneNumber, PasswordResetStatus status);
}