package com.internal.auth.common.reset;

import java.time.LocalDateTime;

/** Common contract for token entities used by the reset engine. */
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
