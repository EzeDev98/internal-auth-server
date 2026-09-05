package com.internal.auth.feature.session.controller;

import com.internal.auth.common.crypto.TokenHasher;
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
import org.junit.jupiter.api.BeforeEach;
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
 * Step 13E (LogoutControl slice): DELETE /session takes no target
 * identifier at all - it looks up the UserSession row whose token_hash
 * matches the caller's OWN bearer token (LogoutServiceImpl, via the same
 * TokenHasher#sha256Hex hashing the real session-tracking path uses) and
 * invalidates only that row. There is no parameter through which a caller
 * could target someone else's session - self-only is structural, not a
 * runtime check - so the interesting case to prove is that a caller
 * holding a session alongside another user's session only ever affects
 * their own row.
 */
@Tag("security-boundary")
class LogoutControlIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserSessionRepository userSessionRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private TokenHasher tokenHasher;

    private ClientApplication client;

    @BeforeEach
    void persistClient() {
        client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
    }

    private UserSession persistActiveSession(Long userId, String rawToken) {
        UserSession session = new UserSession();
        session.setUserId(userId);
        session.setTokenHash(tokenHasher.sha256Hex(rawToken));
        session.setActive(true);
        session.setCreatedAt(LocalDateTime.now());
        return userSessionRepository.save(session);
    }

    @Test
    void logout_withNoToken_isUnauthorized() throws Exception {
        mockMvc.perform(delete("/api/v1/session"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_withNoMatchingSession_returns200WithABusinessFailureEmbedded() throws Exception {
        User user = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
        String token = testTokenMinter.mintAccessToken(client.getId(), user.getUsername(), List.of("basic_access"));
        // Deliberately no matching UserSession row persisted for this token.

        mockMvc.perform(delete("/api/v1/session").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.statusCode").value(400))
                .andExpect(jsonPath("$.data.message").value("No active session found"));
    }

    @Test
    void logout_invalidatesOnlyTheCallersOwnSession() throws Exception {
        User caller = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
        User otherUser = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
        String callerToken = testTokenMinter.mintAccessToken(client.getId(), caller.getUsername(), List.of("basic_access"));
        String otherToken = testTokenMinter.mintAccessToken(client.getId(), otherUser.getUsername(), List.of("basic_access"));
        UserSession callerSession = persistActiveSession(caller.getId(), callerToken);
        UserSession otherSession = persistActiveSession(otherUser.getId(), otherToken);

        mockMvc.perform(delete("/api/v1/session").header("Authorization", "Bearer " + callerToken))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.statusCode").value(200));

        assertThat(userSessionRepository.findById(callerSession.getId()).orElseThrow().isActive()).isFalse();
        assertThat(userSessionRepository.findById(otherSession.getId()).orElseThrow().isActive()).isTrue();
    }
}
