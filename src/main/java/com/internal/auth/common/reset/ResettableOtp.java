package com.internal.auth.common.reset;

import com.internal.auth.feature.passwordreset.enums.PasswordResetStatus;

import java.time.LocalDateTime;

/**
 * Common shape shared by {@code PasswordResetOtp} and any future
 * OTP-then-token-style entity for a different target. PIN reset
 * specifically was evaluated (Step 11D) and deliberately not built in this
 * codebase - "PIN" as originally scoped here meant Wallet.pin, a
 * payments/wallet-domain concept belonging to SyncPoint's own application,
 * not Internal Auth.
 * <p>
 * Implementing this adds no persistence behavior whatsoever — it's a plain
 * Java interface, not a JPA mapping construct, so it has zero effect on
 * table structure, Hibernate mapping, or query behavior. It exists purely
 * so {@code OtpResetEngine} (service.impl) can apply the shared
 * expiry/attempt-limit/match rules once instead of duplicating them per
 * entity type. Implementing classes already expose exactly these
 * getters/setters via Lombok, so implementing this interface requires no
 * change to their fields or annotations.
 */
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

    PasswordResetStatus getStatus();

    void setStatus(PasswordResetStatus status);

    LocalDateTime getVerifiedAt();

    void setVerifiedAt(LocalDateTime verifiedAt);

    LocalDateTime getInvalidatedAt();

    void setInvalidatedAt(LocalDateTime invalidatedAt);

    LocalDateTime getLastSentAt();

    void setLastSentAt(LocalDateTime lastSentAt);
}
