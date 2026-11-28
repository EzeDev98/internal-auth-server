package com.internal.auth.common.reset;

import com.internal.auth.common.crypto.TokenHasher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Base64;

import static com.internal.auth.common.constant.AppConstant.RESET_TOKEN_BYTES;
import static com.internal.auth.common.constant.AppConstant.SECURE_RANDOM;

/** Generates and hashes OTPs and reset tokens. */
@Component
public class OtpService {

    private final PasswordEncoder passwordEncoder;
    private final TokenHasher tokenHasher;

    public OtpService(PasswordEncoder passwordEncoder, TokenHasher tokenHasher) {
        this.passwordEncoder = passwordEncoder;
        this.tokenHasher = tokenHasher;
    }

    public String generateOtp(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(SECURE_RANDOM.nextInt(10));
        }
        return sb.toString();
    }

    public String hashOtp(String rawOtp) {
        return passwordEncoder.encode(rawOtp);
    }

    public boolean matchesOtp(String rawOtp, String otpHash) {
        return passwordEncoder.matches(rawOtp, otpHash);
    }

    public String generateResetToken() {
        byte[] bytes = new byte[RESET_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String hashResetToken(String rawToken) {
        return tokenHasher.sha256Hex(rawToken);
    }
}
