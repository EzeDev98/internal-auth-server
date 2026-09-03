package com.internal.auth.common.reset;

import java.time.LocalDateTime;

/**
 * Common shape shared by {@code PasswordResetToken} and any future
 * OTP-then-token-style token entity for a different target. PIN reset
 * specifically was evaluated (Step 11D) and deliberately not built in this
 * codebase - see {@link ResettableOtp}'s Javadoc for why. See
 * {@link ResettableOtp} also for why this is a plain interface with no
 * persistence implications.
 */
public interface ResettableToken {

    String getTokenHash();

    void setTokenHash(String tokenHash);

    LocalDateTime getExpiresAt();

    void setExpiresAt(LocalDateTime expiresAt);

    boolean isUsed();

    void setUsed(boolean used);

    LocalDateTime getUsedAt();

    void setUsedAt(LocalDateTime usedAt);
}
