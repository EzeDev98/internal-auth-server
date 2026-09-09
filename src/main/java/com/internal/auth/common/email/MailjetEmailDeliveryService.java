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

/**
 * EmailDeliveryService implementation backed by Mailjet's transactional
 * Send API v3.1 - https://dev.mailjet.com/email/guides/send-api-v31/.
 *
 * Activate by setting app.email.provider=mailjet and providing
 * mailjet.api-key / mailjet.secret-key / mailjet.sender-email (see
 * application.properties). Mirrors ContiguityOtpDeliveryService's shape
 * deliberately - same raw-HttpClient-plus-Basic-auth approach, same
 * fail-silently-per-request contract, same reasoning for it: a provider
 * outage must never change what a caller-facing endpoint returns (e.g.
 * EmailVerificationServiceImpl#requestResend's enumeration-resistant
 * "always the same response" contract), so send() below only ever logs
 * on failure, never throws.
 *
 * appName (per-call, from ClientApplication.name - the app the email's
 * owning user actually belongs to, e.g. "SyncPoint" vs "Notare") is used
 * as the sender display name and in the message copy, instead of a single
 * global mailjet.sender-name, so a Notare user no longer gets an email
 * branded "SyncPoint" - same reasoning and pattern as
 * ContiguityOtpDeliveryService's appName handling. mailjet.sender-name is
 * kept as a fallback default for the (should-never-happen) case a caller
 * passes a blank appName.
 */
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

    /** Fallback sender label, used only if a caller passes a blank appName. */
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

    private String safeErrorSummary(String body) {
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode errorMessage = node.path("ErrorMessage");
            if (!errorMessage.isMissingNode()) {
                return errorMessage.asText();
            }
            // v3.1 partial-failure shape: HTTP 200 overall but an
            // individual message can still report "error" - check that
            // too rather than only the top-level error shape.
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