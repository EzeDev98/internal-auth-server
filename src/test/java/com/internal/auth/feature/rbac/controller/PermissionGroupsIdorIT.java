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

/**
 * Step 13C: the confirmed IDOR fix on GET /users/{username}/permission-groups
 * - user A can't fetch user B's groups, can fetch their own, admin can
 * fetch anyone's.
 *
 * This depended on a one-line production fix delivered alongside this test:
 * PermissionController#fetchUserPermissionGroups was
 * @PreAuthorize(Roles.HAS_ADMIN) (create-admin only), which blocked every
 * non-admin caller - including a caller fetching their own username - before
 * the method's own authenticationHelper.requireSelfOrAdmin(username)
 * ownership check ever got a chance to run (Spring Security evaluates
 * @PreAuthorize before a controller method body executes). That's now
 * Roles.HAS_ADMIN_OR_USER, matching what AuthenticationHelper#requireSelfOrAdmin's
 * own Javadoc has always described as this endpoint's intended annotation.
 */
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
