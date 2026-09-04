package com.internal.auth.common.reset.delivery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static com.internal.auth.common.constant.AppConstant.REQUEST_TIMEOUT;

/**
 * OtpDeliveryService implementation backed by Contiguity's plain Text
 * (SMS) API — https://docs.contiguity.com/products/text.
 *
 * We deliberately use Contiguity's raw text-send endpoint rather than its
 * own OTP-management API: this app already owns OTP generation, hashing,
 * expiry, and attempt-limiting (see OtpService / PasswordResetServiceImpl),
 * so Contiguity is used purely as an SMS transport, keeping exactly one
 * source of truth for OTP verification.
 *
 * Activate by setting app.otp.provider=contiguity and providing
 * contiguity.api-key (see application.properties). Contiguity's free tier
 * includes 500 SMS/month at no cost.
 *
 * Delivery failures are logged but never thrown: a provider outage must not
 * change the response returned by the password-reset "request OTP" endpoint,
 * or it would leak whether a phone number is registered (only registered
 * numbers trigger an actual send attempt). The send() helper below is
 * shared by all three OTP purposes so that behavior stays identical for
 * each - only the message text and sender branding differ.
 *
 * appName (per-call, from ClientApplication.name - the app the OTP's
 * owning user actually belongs to, e.g. "SyncPoint" vs "Notare") is used
 * as the SMS sender label instead of the single global
 * contiguity.sender-app-name property, so a Notare user no longer gets a
 * text branded "SyncPoint". That property is kept as a fallback default
 * for the (should-never-happen) case a caller passes a blank appName.
 */
@Service
@ConditionalOnProperty(prefix = "app.otp", name = "provider", havingValue = "contiguity")
public class ContiguityOtpDeliveryService implements OtpDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(ContiguityOtpDeliveryService.class);

    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${contiguity.api-key:}")
    private String apiKey;

    @Value("${contiguity.base-url:https://api.contiguity.com}")
    private String baseUrl;

    /** Fallback sender label, used only if a caller passes a blank appName. */
    @Value("${contiguity.sender-app-name:SyncPoint}")
    private String defaultAppName;

    @Override
    public void sendPasswordResetOtp(String phoneNumber, String otp, String appName) {
        send(phoneNumber, "Your password reset code is " + otp + ". It expires shortly. Do not share this code with anyone.", "password reset", appName);
    }

    @Override
    public void sendPhoneVerificationOtp(String phoneNumber, String otp, String appName) {
        send(phoneNumber, "Your phone verification code is " + otp + ". It expires shortly. Do not share this code with anyone.", "phone verification", appName);
    }

    @Override
    public void sendLoginOtp(String phoneNumber, String otp, String appName) {
        send(phoneNumber, "Your login verification code is " + otp + ". It expires shortly. Do not share this code with anyone.", "login", appName);
    }

    private void send(String phoneNumber, String messageBody, String purpose, String appName) {
        if (apiKey == null || apiKey.isBlank()) {
            log.error("Contiguity is selected as the OTP provider but contiguity.api-key is not configured.");
            return;
        }

        String recipient = toE164(phoneNumber);
        String senderName = (appName == null || appName.isBlank()) ? defaultAppName : appName;
        String message = senderName + ": " + messageBody;

        try {
            String requestBody = objectMapper.writeValueAsString(Map.of(
                    "to", recipient,
                    "message", message
            ));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/send/text"))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Token " + apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("{} OTP sent via Contiguity for a registered phone number (app={})", purpose, senderName);
            } else {
                log.error("Contiguity OTP send failed with status {}: {}", response.statusCode(), safeErrorSummary(response.body()));
            }
        } catch (Exception ex) {
            log.error("Failed to send {} OTP via Contiguity", purpose, ex);
        }
    }

    private String safeErrorSummary(String body) {
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode error = node.path("data").path("error");
            return error.isMissingNode() ? "unknown error" : error.asText();
        } catch (Exception e) {
            return "unparseable error response";
        }
    }

    /**
     * Contiguity requires E.164 (e.g. +2348012345678). This app stores
     * Nigerian numbers without a country code (see the ^\+?[0-9]{11}$
     * phone-format rule enforced at registration/reset time), so we
     * default to +234 when no '+' is present.
     */
    private String toE164(String phoneNumber) {
        if (phoneNumber.startsWith("+")) {
            return phoneNumber;
        }
        String digitsOnly = phoneNumber.replaceFirst("^0", "");
        return "+234" + digitsOnly;
    }
}
