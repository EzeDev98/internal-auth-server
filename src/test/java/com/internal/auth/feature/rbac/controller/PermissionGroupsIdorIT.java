package com.internal.auth.feature.rbac.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/** Verifies users cannot read another user's permission groups. */
@Tag("security-boundary")
class PermissionGroupsIdorIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;

    private ClientApplication client;

    @BeforeEach
    void persistClient() {
        client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
    }

    private User persistUser() {
        return userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
    }

    @Test
    void nonAdminCaller_canFetchTheirOwnPermissionGroups() throws Exception {
        User userA = persistUser();
        String userAToken = testTokenMinter.mintAccessToken(client.getId(), userA.getUsername(), List.of("basic_access"));

        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", userA.getUsername())
                        .header("Authorization", "Bearer " + userAToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void nonAdminCaller_cannotFetchAnotherUsersPermissionGroups() throws Exception {
        User userA = persistUser();
        User userB = persistUser();
        String userAToken = testTokenMinter.mintAccessToken(client.getId(), userA.getUsername(), List.of("basic_access"));

        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", userB.getUsername())
                        .header("Authorization", "Bearer " + userAToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCaller_canFetchAnyUsersPermissionGroups() throws Exception {
        User userA = persistUser();
        String adminToken = testTokenMinter.mintAccessToken(client.getId(), "admin_13c", List.of("create-admin"));

        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", userA.getUsername())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }
}
