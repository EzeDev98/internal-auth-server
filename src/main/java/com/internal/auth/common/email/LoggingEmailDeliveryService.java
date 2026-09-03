package com.internal.auth.common.email;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Development-friendly EmailDeliveryService implementation, mirroring
 * LoggingOtpDeliveryService exactly: active by default (app.email.provider
 * unset or =logging) so the abstraction has a working implementation
 * without a real provider configured. Logs the verification link instead
 * of emailing it.
 *
 * IMPORTANT: logging the raw link is strictly a development convenience,
 * gated behind app.email.log-to-console, which must stay false in
 * production. No real email provider (SendGrid/SES/etc.) is wired up -
 * that's unscoped future work, same status SMS delivery had before
 * ContiguityOtpDeliveryService existed.
 */
@Service
@ConditionalOnProperty(prefix = "app.email", name = "provider", havingValue = "logging", matchIfMissing = true)
public class LoggingEmailDeliveryService implements EmailDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(LoggingEmailDeliveryService.class);

    @Value("${app.email.log-to-console:false}")
    private boolean logToConsole;

    @Override
    public void sendVerificationEmail(String email, String verificationLink) {
        if (logToConsole) {
            log.info("[DEV ONLY] Email verification link for {}: {}", email, verificationLink);
        } else {
            log.info("Email verification link generated for {} (delivery provider not configured)", email);
        }
    }
}
