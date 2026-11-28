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
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static org.assertj.core.api.Assertions.assertThatCode;

/** Tests ContiguityOtpDeliveryService against a WireMock stub of the Contiguity API. */
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

        service.sendPhoneVerificationOtp("+2348012345678", "654321", "SyncPoint");

        wireMockServer.verify(postRequestedFor(urlEqualTo("/send/text"))
                .withRequestBody(matchingJsonPath("$.to", equalTo("+2348012345678")))
                .withRequestBody(matchingJsonPath("$.message", containing("phone verification code is 654321"))));
    }

    @Test
    void send_swallowsTheFailure_whenProviderRespondsWithAnErrorStatus() {
        wireMockServer.stubFor(post(urlEqualTo("/send/text"))
                .willReturn(aResponse().withStatus(500).withBody("{\"data\":{\"error\":\"provider outage\"}}")));

        assertThatCode(() -> service.sendPasswordResetOtp("08012345678", "123456", "SyncPoint"))
                .doesNotThrowAnyException();

        wireMockServer.verify(postRequestedFor(urlEqualTo("/send/text")));
    }

    @Test
    void send_swallowsTheFailure_whenTheProviderIsUnreachable() {
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
