package com.internal.auth.feature.session.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.List;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 8C. UserSessionController's own Javadoc always described
 * DELETE ${app.title}/users/{username}/sessions as admin-only; this is the
 * regression test for the confirmed broken-access-control gap that fix
 * closed - an authenticated caller with no admin role must never be able to
 * force-terminate another user's session, and a genuine admin caller must
 * still be able to.
 */
@Tag("security-boundary")
class UserSessionControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserSessionRepository userSessionRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;

    @Test
    void nonAdminCaller_isForbiddenFromForceLoggingOutAnotherUser() throws Exception {
        ClientApplication client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        User target = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
        String nonAdminToken = testTokenMinter.mintAccessToken(client.getId(), "some-basic-user", List.of("basic_access"));

        mockMvc.perform(delete("/api/v1/users/{username}/sessions", target.getUsername())
                        .param("clientId", client.getClientId())
                        .header("Authorization", "Bearer " + nonAdminToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void callerWithNoBearerToken_isUnauthorized() throws Exception {
        ClientApplication client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        User target = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());

        mockMvc.perform(delete("/api/v1/users/{username}/sessions", target.getUsername())
                        .param("clientId", client.getClientId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminCaller_forceLogsOutTheTargetUsersActiveSession() throws Exception {
        ClientApplication client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        User target = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());

        UserSession activeSession = new UserSession();
        activeSession.setUserId(target.getId());
        activeSession.setTokenHash("irrelevant-hash-" + target.getId());
        activeSession.setActive(true);
        activeSession.setCreatedAt(LocalDateTime.now());
        userSessionRepository.save(activeSession);

        String adminToken = testTokenMinter.mintAccessToken(client.getId(), "some-admin", List.of("create-admin"));

        mockMvc.perform(delete("/api/v1/users/{username}/sessions", target.getUsername())
                        .param("clientId", client.getClientId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.status").value(200))
                .andExpect(jsonPath("$.data.message").value("Session successfully invalidated for user " + target.getUsername()));

        assertThat(userSessionRepository.findByUserIdAndIsActiveTrue(target.getId())).isEmpty();
    }

    @Test
    void adminCaller_unknownUsername_getsA404BusinessResultInsideTheStandardOkEnvelope() throws Exception {
        ClientApplication client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        String adminToken = testTokenMinter.mintAccessToken(client.getId(), "some-admin", List.of("create-admin"));

        mockMvc.perform(delete("/api/v1/users/{username}/sessions", "no-such-user")
                        .param("clientId", client.getClientId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value(404));
    }
}
