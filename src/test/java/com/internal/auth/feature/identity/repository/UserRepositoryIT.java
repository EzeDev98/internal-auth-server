package com.internal.auth.feature.identity.repository;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Integration tests for UserRepository against a migrated database. */
class UserRepositoryIT extends IntegrationTestBase {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ClientApplicationRepository clientApplicationRepository;

    @Test
    void findByUsernameAndClientApplicationId_doesNotMatchTheSameUsernameInAnotherTenant() {
        ClientApplication tenantA = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        ClientApplication tenantB = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.save(UserTestDataBuilder.aUser().withUsername("shared_name").withClientApplicationId(tenantA.getId()).build());
        User tenantBUser = userRepository.save(UserTestDataBuilder.aUser().withUsername("shared_name").withClientApplicationId(tenantB.getId()).build());

        Optional<User> foundInTenantB = userRepository.findByUsernameAndClientApplicationId("shared_name", tenantB.getId());

        assertThat(foundInTenantB).contains(tenantBUser);
    }

    @Test
    void findAllByUsername_returnsEveryTenantsMatch_deliberatelyUnscoped() {
        ClientApplication tenantA = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        ClientApplication tenantB = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        User tenantAUser = userRepository.save(UserTestDataBuilder.aUser().withUsername("cross_tenant_name").withClientApplicationId(tenantA.getId()).build());
        User tenantBUser = userRepository.save(UserTestDataBuilder.aUser().withUsername("cross_tenant_name").withClientApplicationId(tenantB.getId()).build());

        List<User> matches = userRepository.findAllByUsername("cross_tenant_name");

        assertThat(matches).containsExactlyInAnyOrder(tenantAUser, tenantBUser);
    }

    @Test
    void findByPhoneNumberAndClientApplicationId_scopedByTenant() {
        ClientApplication tenantA = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        ClientApplication tenantB = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.save(UserTestDataBuilder.aUser().withPhoneNumber("08012340000").withClientApplicationId(tenantA.getId()).build());
        User tenantBUser = userRepository.save(UserTestDataBuilder.aUser().withPhoneNumber("08012340000").withClientApplicationId(tenantB.getId()).build());

        Optional<User> found = userRepository.findByPhoneNumberAndClientApplicationId("08012340000", tenantB.getId());

        assertThat(found).contains(tenantBUser);
    }

    @Test
    void findByEmailAndClientApplicationId_scopedByTenant() {
        ClientApplication tenantA = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        ClientApplication tenantB = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.save(UserTestDataBuilder.aUser().withEmail("shared@example.com").withClientApplicationId(tenantA.getId()).build());
        User tenantBUser = userRepository.save(UserTestDataBuilder.aUser().withEmail("shared@example.com").withClientApplicationId(tenantB.getId()).build());

        Optional<User> found = userRepository.findByEmailAndClientApplicationId("shared@example.com", tenantB.getId());

        assertThat(found).contains(tenantBUser);
    }

    @Test
    void duplicateUsernameWithinTheSameClientApplication_violatesTheCompositeUniqueConstraint() {
        ClientApplication tenant = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.saveAndFlush(UserTestDataBuilder.aUser().withUsername("dup_user").withClientApplicationId(tenant.getId()).build());

        assertThatThrownBy(() ->
                userRepository.saveAndFlush(UserTestDataBuilder.aUser().withUsername("dup_user").withClientApplicationId(tenant.getId()).build()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void sameUsernameAcrossDifferentClientApplications_isAllowed_provingTheConstraintIsTrulyComposite() {
        ClientApplication tenantA = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        ClientApplication tenantB = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.saveAndFlush(UserTestDataBuilder.aUser().withUsername("same_name_both_tenants").withClientApplicationId(tenantA.getId()).build());

        User tenantBUser = userRepository.saveAndFlush(
                UserTestDataBuilder.aUser().withUsername("same_name_both_tenants").withClientApplicationId(tenantB.getId()).build());

        assertThat(tenantBUser.getId()).isNotNull();
    }

    @Test
    void duplicatePhoneNumberWithinTheSameClientApplication_violatesTheCompositeUniqueConstraint() {
        ClientApplication tenant = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.saveAndFlush(UserTestDataBuilder.aUser().withPhoneNumber("08055550001").withClientApplicationId(tenant.getId()).build());

        assertThatThrownBy(() ->
                userRepository.saveAndFlush(UserTestDataBuilder.aUser().withPhoneNumber("08055550001").withClientApplicationId(tenant.getId()).build()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void duplicateEmailWithinTheSameClientApplication_violatesTheCompositeUniqueConstraint() {
        ClientApplication tenant = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        userRepository.saveAndFlush(UserTestDataBuilder.aUser().withEmail("dup@example.com").withClientApplicationId(tenant.getId()).build());

        assertThatThrownBy(() ->
                userRepository.saveAndFlush(UserTestDataBuilder.aUser().withEmail("dup@example.com").withClientApplicationId(tenant.getId()).build()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
