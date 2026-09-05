package com.internal.auth.common.reset.delivery;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Step 16A: ContiguityOtpDeliveryService against a WireMock stub of
 * Contiguity's real POST /send/text endpoint - no Spring context, no DB,
 * no Redis needed (fast *Test.java, not *IT.java: this class has exactly
 * one collaborator, java.net.http.HttpClient, which talks to whatever
 * contiguity.base-url points at).
 *
 * <p>apiKey/baseUrl/defaultAppName are private @Value fields with no
 * setters (populated by Spring in production) - ReflectionTestUtils
 * fills them in directly against a plain `new` instance, same pattern
 * as any other framework-free unit test of a @Value-annotated class.
 *
 * <p>Ground-truthed ContiguityOtpDeliveryService#send: the request body
 * is {"to": e164Phone, "message": "appName: <purpose text>"}, headers are
 * Content-Type: application/json and Authorization: "Token " + apiKey,
 * and toE164() strips a leading "0" and prepends "+234" for any number
 * not already starting with "+". The whole HTTP round trip is wrapped in
 * one try/catch (Exception ex) - both a non-2xx response AND a thrown
 * exception (e.g. connection refused) are only logged, never
 * propagated, because a provider outage must not change the
 * password-reset "request OTP" endpoint's response (see this class's own
 * Javadoc on user-enumeration protection).
 */
class ContiguityOtpDeliveryServiceTest {

    private static final String API_KEY = "test-contiguity-api-key";

    private static WireMockServer wireMockServer;

    private ContiguityOtpDeliveryService service;

    @BeforeAll
    static void startWireMock() {
        wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMockServer.start();
    }

    @AfterAll
    static void stopWireMock() {
        wireMockServer.stop();
    }

    @BeforeEach
    void setUp() {
        wireMockServer.resetAll();

        service = new ContiguityOtpDeliveryService();
        ReflectionTestUtils.setField(service, "apiKey", API_KEY);
        ReflectionTestUtils.setField(service, "baseUrl", wireMockServer.baseUrl());
        ReflectionTestUtils.setField(service, "defaultAppName", "SyncPoint");
    }

    @AfterEach
    void tearDown() {
        wireMockServer.resetAll();
    }

    @Test
    void sendPasswordResetOtp_postsCorrectPayloadAndAuthHeader() {
        wireMockServer.stubFor(post(urlEqualTo("/send/text"))
                .willReturn(aResponse().withStatus(200)));

        // Leading-zero local format - toE164 must strip the "0" and
        // prepend "+234" rather than just concatenating.
        service.sendPasswordResetOtp("08012345678", "123456", "Notare");

        wireMockServer.verify(postRequestedFor(urlEqualTo("/send/text"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withHeader("Authorization", equalTo("Token " + API_KEY))
                .withRequestBody(matchingJsonPath("$.to", equalTo("+2348012345678")))
                .withRequestBody(matchingJsonPath("$.message",
                        equalTo("Notare: Your password reset code is 123456. It expires shortly. Do not share this code with anyone."))));
    }

    @Test
    void sendPhoneVerificationOtp_sendsThePhoneVerificationSpecificMessage_notThePasswordResetOne() {
        wireMockServer.stubFor(post(urlEqualTo("/send/text"))
                .willReturn(aResponse().withStatus(200)));

        // Already E.164 - toE164 must pass it through unchanged.
        service.sendPhoneVerificationOtp("+2348012345678", "654321", "SyncPoint");

        wireMockServer.verify(postRequestedFor(urlEqualTo("/send/text"))
                .withRequestBody(matchingJsonPath("$.to", equalTo("+2348012345678")))
                .withRequestBody(matchingJsonPath("$.message", containing("phone verification code is 654321"))));
    }

    @Test
    void sendLoginOtp_fallsBackToDefaultAppName_whenCallerAppNameIsBlank() {
        wireMockServer.stubFor(post(urlEqualTo("/send/text"))
                .willReturn(aResponse().withStatus(200)));

        service.sendLoginOtp("+2348012345678", "111222", "");

        wireMockServer.verify(postRequestedFor(urlEqualTo("/send/text"))
                .withRequestBody(matchingJsonPath("$.message", containing("login verification code is 111222")))
                // blank appName -> falls back to the injected defaultAppName ("SyncPoint"), not an empty label.
                .withRequestBody(equalToJson("{\"to\":\"+2348012345678\",\"message\":\"SyncPoint: Your login verification code is 111222. It expires shortly. Do not share this code with anyone.\"}", true, true)));
    }

    @Test
    void send_swallowsTheFailure_whenProviderRespondsWithAnErrorStatus() {
        wireMockServer.stubFor(post(urlEqualTo("/send/text"))
                .willReturn(aResponse().withStatus(500).withBody("{\"data\":{\"error\":\"provider outage\"}}")));

        // Must not throw - a 500 from Contiguity is logged, not propagated,
        // per this class's Javadoc on why enumeration protection depends
        // on this never surfacing to the caller.
        assertThatCode(() -> service.sendPasswordResetOtp("08012345678", "123456", "SyncPoint"))
                .doesNotThrowAnyException();

        // The call genuinely reached the provider and failed there -
        // this isn't passing merely because nothing was sent at all.
        wireMockServer.verify(postRequestedFor(urlEqualTo("/send/text")));
    }

    @Test
    void send_swallowsTheFailure_whenTheProviderIsUnreachable() {
        // Nothing listens on this port - HttpClient#send throws
        // ConnectException, caught by send()'s own try/catch(Exception).
        ReflectionTestUtils.setField(service, "baseUrl", "http://127.0.0.1:1");

        assertThatCode(() -> service.sendPasswordResetOtp("08012345678", "123456", "SyncPoint"))
                .doesNotThrowAnyException();
    }

    @Test
    void send_doesNothingAndNeverCallsTheProvider_whenApiKeyIsNotConfigured() {
        ReflectionTestUtils.setField(service, "apiKey", "");

        assertThatCode(() -> service.sendPasswordResetOtp("08012345678", "123456", "SyncPoint"))
                .doesNotThrowAnyException();

        wireMockServer.verify(0, postRequestedFor(urlEqualTo("/send/text")));
    }
}
