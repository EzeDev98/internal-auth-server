package com.internal.auth.common.email;

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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static com.internal.auth.common.constant.AppConstant.REQUEST_TIMEOUT;

/** Email delivery implementation backed by the Mailjet Send API. */
@Service
@ConditionalOnProperty(prefix = "app.email", name = "provider", havingValue = "mailjet")
public class MailjetEmailDeliveryService implements EmailDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(MailjetEmailDeliveryService.class);
    private static final String SEND_URL = "https://api.mailjet.com/v3.1/send";

    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${mailjet.api-key:}")
    private String apiKey;

    @Value("${mailjet.secret-key:}")
    private String secretKey;

    @Value("${mailjet.sender-email:}")
    private String senderEmail;

    @Value("${mailjet.sender-name:SyncPoint}")
    private String defaultSenderName;

    @Override
    public void sendVerificationEmail(String email, String verificationLink, String appName) {
        if (apiKey == null || apiKey.isBlank() || secretKey == null || secretKey.isBlank()) {
            log.error("Mailjet is selected as the email provider but mailjet.api-key/mailjet.secret-key are not configured.");
            return;
        }
        if (senderEmail == null || senderEmail.isBlank()) {
            log.error("Mailjet is selected as the email provider but mailjet.sender-email is not configured.");
            return;
        }

        String senderName = (appName == null || appName.isBlank()) ? defaultSenderName : appName;
        String subject = "Verify your " + senderName + " email address";
        String textPart = "Verify your email address for " + senderName + " by opening this link: " + verificationLink
                + "\n\nIf you didn't request this, you can safely ignore this message.";
        String htmlPart = "<p>Verify your email address for <strong>" + senderName + "</strong> by clicking the link below.</p>"
                + "<p><a href=\"" + verificationLink + "\">Verify email</a></p>"
                + "<p>If you didn't request this, you can safely ignore this message.</p>";

        try {
            Map<String, Object> message = Map.of(
                    "From", Map.of("Email", senderEmail, "Name", senderName),
                    "To", List.of(Map.of("Email", email)),
                    "Subject", subject,
                    "TextPart", textPart,
                    "HTMLPart", htmlPart
            );
            String requestBody = objectMapper.writeValueAsString(Map.of("Messages", List.of(message)));

            String basicAuth = Base64.getEncoder().encodeToString(
                    (apiKey + ":" + secretKey).getBytes(StandardCharsets.UTF_8));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(SEND_URL))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Basic " + basicAuth)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("Verification email sent via Mailjet for a registered email address (app={})", senderName);
            } else {
                log.error("Mailjet email send failed with status {}: {}", response.statusCode(), safeErrorSummary(response.body()));
            }
        } catch (Exception ex) {
            log.error("Failed to send verification email via Mailjet", ex);
        }
    }

    @Override
    public void sendPasswordResetOtpEmail(String email, String otp, String appName) {
        if (apiKey == null || apiKey.isBlank() || secretKey == null || secretKey.isBlank()
                || senderEmail == null || senderEmail.isBlank()) {
            log.error("Mailjet is selected as the email provider but its api-key/secret-key/sender-email are not fully configured.");
            return;
        }

        String senderName = (appName == null || appName.isBlank()) ? defaultSenderName : appName;
        String subject = "Your " + senderName + " password reset code";
        String textPart = "Your " + senderName + " password reset code is: " + otp
                + "\n\nIt expires shortly. If you didn't request this, you can safely ignore this message.";
        String htmlPart = "<p>Your <strong>" + senderName + "</strong> password reset code is:</p>"
                + "<p style=\"font-size:24px;letter-spacing:4px\"><strong>" + otp + "</strong></p>"
                + "<p>It expires shortly. If you didn't request this, you can safely ignore this message.</p>";

        try {
            Map<String, Object> message = Map.of(
                    "From", Map.of("Email", senderEmail, "Name", senderName),
                    "To", List.of(Map.of("Email", email)),
                    "Subject", subject,
                    "TextPart", textPart,
                    "HTMLPart", htmlPart
            );
            String requestBody = objectMapper.writeValueAsString(Map.of("Messages", List.of(message)));
            String basicAuth = Base64.getEncoder().encodeToString(
                    (apiKey + ":" + secretKey).getBytes(StandardCharsets.UTF_8));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(SEND_URL))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Basic " + basicAuth)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("Password reset email sent via Mailjet (app={})", senderName);
            } else {
                log.error("Mailjet password reset email failed with status {}: {}", response.statusCode(), safeErrorSummary(response.body()));
            }
        } catch (Exception ex) {
            log.error("Failed to send password reset email via Mailjet", ex);
        }
    }

    private String safeErrorSummary(String body) {
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode errorMessage = node.path("ErrorMessage");
            if (!errorMessage.isMissingNode()) {
                return errorMessage.asText();
            }
            JsonNode messages = node.path("Messages");
            if (messages.isArray() && !messages.isEmpty()) {
                return messages.get(0).path("Errors").toString();
            }
            return "unknown error";
        } catch (Exception e) {
            return "unparseable error response";
        }
    }
}
