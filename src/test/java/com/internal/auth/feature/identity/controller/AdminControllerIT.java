package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.feature.identity.dto.request.AdminRegisterRequest;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 12B (AdminController): the full bootstrap-then-lock sequence -
 * register creates the very first admin with no credentials of any kind
 * (see AdminController's own class Javadoc - "/register" is permitAll by
 * definition, since the first admin has nothing to authenticate with yet),
 * that admin can immediately log in through the same LoginService every
 * regular user uses and receive a real access token, and a second,
 * unauthenticated /register attempt is correctly rejected once the
 * create-admin role is held by anyone (AdminRegistrationServiceImpl's
 * self-limiting gate -> AccessDeniedException -> GlobalExceptionHandler's
 * 403 FORBIDDEN mapping).
 *
 * UserRolesRepository#existsByRoleRoleName is deliberately global, not
 * scoped by client_application_id (see that method's own Javadoc), and
 * this suite's Postgres container is a reused singleton across the whole
 * IT run (IntegrationTestBase) - so this class clears any prior
 * create-admin state in @BeforeEach rather than assuming it's the only
 * test class that will ever touch that role, keeping the "no admin exists
 * yet" precondition true regardless of run order.
 */
class AdminControllerIT extends IntegrationTestBase {

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void clearAnyPriorAdminState() {
        jdbcTemplate.update(
                "DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE role_name = ?)",
                AppConstant.ADMIN_ROLE);
        jdbcTemplate.update(
                "DELETE FROM users WHERE client_application_id IN "
                        + "(SELECT id FROM client_applications WHERE client_id = ?)",
                AppConstant.INTERNAL_ADMIN_CLIENT_ID);
    }

    @Test
    void bootstrapThenLock_registerLoginThenSecondRegisterAttempt() throws Exception {
        AdminRegisterRequest firstAdmin = new AdminRegisterRequest(
                "root_admin_12b", "+23480001201", "rootadmin12b@user.com", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/admin/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstAdmin)))
                .andExpect(status().isCreated())
                .andExpect(success())
                .andExpect(jsonPath("$.data.username").value("root_admin_12b"));

        LoginRequest loginRequest = new LoginRequest("root_admin_12b", "Passw0rd!");

        mockMvc.perform(post("/api/v1/admin/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.mfaRequired").value(false))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.username").value("root_admin_12b"));

        AdminRegisterRequest secondAdmin = new AdminRegisterRequest(
                "second_admin_12b", "+23480001202", "secondadmin12b@user.com", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/admin/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secondAdmin)))
                .andExpect(status().isForbidden());
    }
}
