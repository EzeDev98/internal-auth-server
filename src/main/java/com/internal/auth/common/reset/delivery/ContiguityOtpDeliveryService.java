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

/** OTP delivery implementation that sends SMS through the Contiguity API. */
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

    private String toE164(String phoneNumber) {
        if (phoneNumber.startsWith("+")) {
            return phoneNumber;
        }
        String digitsOnly = phoneNumber.replaceFirst("^0", "");
        return "+234" + digitsOnly;
    }
}
