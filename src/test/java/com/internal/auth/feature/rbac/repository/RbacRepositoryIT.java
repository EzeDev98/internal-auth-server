package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.UserRole;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.PermissionGroupTestDataBuilder;
import com.internal.auth.testsupport.builder.RoleTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Step 9B/9C/9D. Runs against a real, throwaway Postgres with every Flyway
 * migration applied (via IntegrationTestBase, same rationale as
 * UserRepositoryIT's class javadoc) rather than a lighter @DataJpaTest/H2
 * slice.
 *
 * Covers the RBAC custom queries that AdminRegistrationServiceImpl and
 * UserRoleServiceImpl actually depend on: the tenant-scoped vs
 * deliberately-global read paths (RolesRepository is global by product
 * decision - see RoleTestDataBuilder's own javadoc), the V20 name-uniqueness
 * constraints, and - the part a mock can never prove - that
 * findByRoleNameForUpdate's PESSIMISTIC_WRITE lock genuinely blocks a
 * second concurrent caller at the database level rather than just
 * compiling with the right annotation.
 */
class RbacRepositoryIT extends IntegrationTestBase {

    @Autowired
    private RolesRepository rolesRepository;
    @Autowired
    private UserRolesRepository userRolesRepository;
    @Autowired
    private PermissionGroupsRepository permissionGroupsRepository;
    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    private TransactionTemplate transactionTemplate;

    @BeforeEach
    void setUpTransactionTemplate() {
        transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Test
    void findRolesByUserId_returnsOnlyThatUsersOwnRoles() {
        ClientApplication tenant = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        User userOne = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(tenant.getId()).build());
        User userTwo = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(tenant.getId()).build());
        Role roleOne = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        Role roleTwo = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        link(userOne, roleOne);
        link(userTwo, roleTwo);

        List<Role> foundRoles = userRolesRepository.findRolesByUserId(userOne.getId());

        assertThat(foundRoles).containsExactly(roleOne);
    }

    @Test
    void existsByRoleRoleName_true_whenAnyUserAnywhereHoldsThatRole_globalNotTenantScoped() {
        ClientApplication tenant = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        User userInThatTenant = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(tenant.getId()).build());
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        link(userInThatTenant, role);

        // No clientApplicationId/tenant is passed to this query at all - it
        // is true purely because *some* user, in *some* tenant, holds this
        // role, matching AdminRegistrationServiceImpl's own use of it to
        // self-limit admin bootstrap system-wide rather than per tenant.
        assertThat(userRolesRepository.existsByRoleRoleName(role.getRoleName())).isTrue();
        assertThat(userRolesRepository.existsByRoleRoleName("role-nobody-anywhere-holds")).isFalse();
    }

    @Test
    void findByRoleNameForUpdate_findsTheRowByName() {
        Role role = rolesRepository.saveAndFlush(RoleTestDataBuilder.aRole().withRoleName("lockable-role").build());

        Optional<Role> found = rolesRepository.findByRoleNameForUpdate("lockable-role");

        assertThat(found).contains(role);
    }

    @Test
    void duplicateRoleName_violatesTheV20UniqueConstraint() {
        rolesRepository.saveAndFlush(RoleTestDataBuilder.aRole().withRoleName("dup-role-name").build());

        assertThatThrownBy(() ->
                rolesRepository.saveAndFlush(RoleTestDataBuilder.aRole().withRoleName("dup-role-name").build()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void duplicatePermissionGroupName_violatesTheV20UniqueConstraint() {
        permissionGroupsRepository.saveAndFlush(PermissionGroupTestDataBuilder.aPermissionGroup().withGroupName("dup-group-name").build());

        assertThatThrownBy(() ->
                permissionGroupsRepository.saveAndFlush(PermissionGroupTestDataBuilder.aPermissionGroup().withGroupName("dup-group-name").build()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    /**
     * Proves findByRoleNameForUpdate's @Lock(PESSIMISTIC_WRITE) is a real
     * SELECT ... FOR UPDATE, not a no-op annotation: a second transaction
     * that tries to lock the same row must genuinely wait in the database
     * until the first transaction commits, rather than reading through
     * immediately. First transaction holds the lock, signals it has it,
     * then sleeps 500ms *after* confirming the second caller has already
     * issued its own locking query - so the second caller's measured
     * elapsed time is a real wait on Postgres, not a race against this
     * test's own thread scheduling.
     */
    @Test
    void findByRoleNameForUpdate_pessimisticWriteLock_secondCallerGenuinelyBlocksUntilTheFirstCommits() throws Exception {
        rolesRepository.saveAndFlush(RoleTestDataBuilder.aRole().withRoleName("lock-target-role").build());

        CountDownLatch firstHasLock = new CountDownLatch(1);
        CountDownLatch secondIsAboutToQuery = new CountDownLatch(1);
        AtomicLong secondCallElapsedMillis = new AtomicLong();
        ExecutorService executor = Executors.newFixedThreadPool(2);

        Future<?> firstTransaction = executor.submit(() -> transactionTemplate.executeWithoutResult(status -> {
            rolesRepository.findByRoleNameForUpdate("lock-target-role");
            firstHasLock.countDown();
            await(secondIsAboutToQuery);
            sleepMillis(500);
        }));

        await(firstHasLock);

        Future<?> secondTransaction = executor.submit(() -> transactionTemplate.executeWithoutResult(status -> {
            secondIsAboutToQuery.countDown();
            long start = System.currentTimeMillis();
            rolesRepository.findByRoleNameForUpdate("lock-target-role");
            secondCallElapsedMillis.set(System.currentTimeMillis() - start);
        }));

        firstTransaction.get(10, TimeUnit.SECONDS);
        secondTransaction.get(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(secondCallElapsedMillis.get())
                .as("second caller's SELECT ... FOR UPDATE must genuinely block until the first transaction commits")
                .isGreaterThanOrEqualTo(400);
    }

    private UserRole link(User user, Role role) {
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);
        userRole.setCreatedAt(LocalDateTime.now());
        return userRolesRepository.save(userRole);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting on latch");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static void sleepMillis(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
