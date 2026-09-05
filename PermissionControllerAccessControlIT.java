package com.internal.auth.feature.rbac.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.stream.Stream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 13A: PermissionController's full route set. Every one of its 18
 * endpoints is @PreAuthorize(Roles.HAS_ADMIN) (create-admin only), so this
 * sweeps all of them with the two universal cases: no bearer token at all
 * (401, GlobalExceptionHandler's AuthenticationException handler) and a
 * real, validly-signed token that simply lacks the create-admin authority
 * (403, the @PreAuthorize denial -> GlobalExceptionHandler's
 * AccessDeniedException handler). @PreAuthorize's advice runs before a
 * controller method body ever executes, so neither case needs any real
 * domain data behind the path variables below for the assertion to be
 * meaningful - only the "200 with an admin token" case (real preconditions,
 * real per-operation success status) needs that, and is covered separately
 * in PermissionControllerAdminHappyPathIT.
 *
 * Request bodies are syntactically valid JSON matching each endpoint's own
 * DTO with placeholder values: @RequestBody argument resolution happens
 * before @PreAuthorize's advice runs, so a malformed body would fail
 * before the security check and the test would prove the wrong thing.
 */
class PermissionControllerAccessControlIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;

    private String nonAdminToken;

    @BeforeEach
    void mintNonAdminToken() {
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication().build());
        nonAdminToken = testTokenMinter.mintAccessToken(client.getId(), "non_admin_13a", List.of("basic_access"));
    }

    private record Route(String method, String path, String body) {
        @Override
        public String toString() {
            return method + " " + path;
        }
    }

    private static Stream<Route> routes() {
        return Stream.of(
                new Route("POST", "/api/v1/roles", "{\"roleName\":\"r\",\"description\":\"d\"}"),
                new Route("POST", "/api/v1/groups", "{\"groupName\":\"g\",\"description\":\"d\"}"),
                new Route("POST", "/api/v1/groups/parent/subgroups", "{\"groupName\":\"g\",\"description\":\"d\"}"),
                new Route("POST", "/api/v1/service/users/someone/roles", "{\"roleName\":\"r\"}"),
                new Route("POST", "/api/v1/users/someone/roles", "{\"roleName\":\"r\"}"),
                new Route("POST", "/api/v1/groups/g/roles", "{\"roleName\":\"r\"}"),
                new Route("POST", "/api/v1/groups/parent/subgroups/sub/roles", "{\"roleName\":\"r\"}"),
                new Route("POST", "/api/v1/groups/g/users", "{\"username\":\"u\"}"),
                new Route("POST", "/api/v1/groups/parent/subgroups/sub/users", "{\"username\":\"u\"}"),
                new Route("POST", "/api/v1/groups/parent/users/someone/subgroups", "{\"subGroupNames\":[\"sub\"]}"),
                new Route("DELETE", "/api/v1/users/someone/roles/r", null),
                new Route("DELETE", "/api/v1/groups/g/users/someone", null),
                new Route("DELETE", "/api/v1/groups/g", null),
                new Route("GET", "/api/v1/groups/g", null),
                new Route("GET", "/api/v1/groups/parent/subgroups/sub", null),
                new Route("GET", "/api/v1/groups/parent/subgroups/sub/users", null),
                new Route("GET", "/api/v1/users/someone/permission-groups", null),
                new Route("GET", "/api/v1/users/someone/roles", null)
        );
    }

    private MockHttpServletRequestBuilder toRequest(Route route, String bearerToken) {
        MockHttpServletRequestBuilder builder = switch (route.method()) {
            case "POST" -> post(route.path());
            case "DELETE" -> delete(route.path());
            case "GET" -> get(route.path());
            default -> throw new IllegalStateException("Unsupported method " + route.method());
        };
        if (route.body() != null) {
            builder = builder.contentType(MediaType.APPLICATION_JSON).content(route.body());
        }
        if (bearerToken != null) {
            builder = builder.header("Authorization", "Bearer " + bearerToken);
        }
        return builder;
    }

    @ParameterizedTest(name = "[{index}] {0} with no bearer token is unauthorized")
    @MethodSource("routes")
    void noToken_isUnauthorized(Route route) throws Exception {
        mockMvc.perform(toRequest(route, null)).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest(name = "[{index}] {0} with a non-admin token is forbidden")
    @MethodSource("routes")
    void nonAdminToken_isForbidden(Route route) throws Exception {
        mockMvc.perform(toRequest(route, nonAdminToken)).andExpect(status().isForbidden());
    }
}
