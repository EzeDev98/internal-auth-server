package com.internal.auth.common.reset;


import java.time.LocalDateTime;

/** Common contract for OTP entities used by the reset engine. */
public interface ResettableOtp {

    String getPhoneNumber();

    void setPhoneNumber(String phoneNumber);

    String getOtpHash();

    void setOtpHash(String otpHash);

    LocalDateTime getExpiresAt();

    void setExpiresAt(LocalDateTime expiresAt);

    int getAttemptCount();

    void setAttemptCount(int attemptCount);

    int getMaxAttempts();

    void setMaxAttempts(int maxAttempts);

    ResetStatus getStatus();

    void setStatus(ResetStatus status);

    LocalDateTime getVerifiedAt();

    void setVerifiedAt(LocalDateTime verifiedAt);

    LocalDateTime getInvalidatedAt();

    void setInvalidatedAt(LocalDateTime invalidatedAt);

    LocalDateTime getLastSentAt();

    void setLastSentAt(LocalDateTime lastSentAt);
}
