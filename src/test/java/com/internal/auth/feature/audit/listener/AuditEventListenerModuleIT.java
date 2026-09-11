package com.internal.auth.feature.audit.listener;
import org.springframework.test.context.TestPropertySource;

import com.internal.auth.feature.audit.enums.AuditAction;
import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.feature.audit.model.AuditLog;
import com.internal.auth.feature.audit.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.modulith.events.IncompleteEventPublications;
import org.springframework.modulith.events.core.EventPublicationRegistry;
import org.springframework.modulith.test.ApplicationModuleTest;
import org.springframework.modulith.test.Scenario;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

/**
 * Step 17A.
 *
 * Two things live in this one class:
 *
 * 1. {@code @ApplicationModuleTest} itself IS the module-boundary check -
 *    {@code verifyAutomatically} (on by default) runs
 *    {@code ApplicationModules.of(...).verify()} against the "audit"
 *    module (see feature/audit/package-info.java) before either test
 *    method runs, and restricts this test's component scan to just that
 *    module's own packages. If a future change makes AuditEventListener
 *    reach for something outside feature.audit without going through the
 *    {@code event} named interface (fix 3b of fix3modulithboundaries.md -
 *    callers publish {@code UserLoggedInEvent} directly now; there is no
 *    AuditService/AuditServiceImpl facade anymore), this fails to even
 *    start.
 *
 * 2. The two @Test methods cover AuditEventListener's actual documented
 *    behavior: the happy path (an event gets persisted as an audit row),
 *    and the durability path from its own Javadoc - a crash between the
 *    business transaction committing and the listener finishing its write
 *    leaves a durable, incomplete row in event_publication rather than
 *    losing the event, and that row is exactly what a real restart's
 *    spring.modulith.events.republish-outstanding-events-on-restart
 *    resubmission logic replays. We exercise that resubmission directly
 *    via EventPublicationRegistry instead of actually restarting the JVM.
 *
 * Requires spring.modulith.detection-strategy=explicitly-annotated, set
 * only in application-test.properties - see that file's comment. No Redis
 * container here (unlike IntegrationTestBase) - nothing in the audit
 * module needs it.
 */
@ActiveProfiles("test")
@TestPropertySource(properties = "spring.autoconfigure.exclude=org.redisson.spring.starter.RedissonAutoConfigurationV4")
@ApplicationModuleTest
class AuditEventListenerModuleIT {

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withDatabaseName("internal_auth_audit_module_test")
                    .withUsername("test")
                    .withPassword("test")
                    .withReuse(true);

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void registerContainerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @MockitoSpyBean
    private AuditLogRepository auditLogRepository;

    @Autowired
    private EventPublicationRegistry eventPublicationRegistry;

    @Autowired
    private IncompleteEventPublications incompleteEventPublications;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void resetState() {
        reset(auditLogRepository);
        jdbcTemplate.update("DELETE FROM audit_log");
        jdbcTemplate.update("DELETE FROM event_publication");
    }

    @Test
    void publishedLoginEvent_isPersistedAsAuditLogByTheListener(Scenario scenario) {
        UserLoggedInEvent event = new UserLoggedInEvent(101L, "moses.dev", 7L);

        scenario.publish(event)
                .andWaitForStateChange(auditLogRepository::findAll, logs -> !logs.isEmpty())
                .andVerify(logs -> {
                    assertThat(logs).hasSize(1);
                    AuditLog log = logs.get(0);
                    assertThat(log.getAction()).isEqualTo(AuditAction.LOGIN_SUCCESS.name());
                    assertThat(log.getActorUserId()).isEqualTo(101L);
                    assertThat(log.getActorUsername()).isEqualTo("moses.dev");
                    assertThat(log.getClientApplicationId()).isEqualTo(7L);
                });
    }

    @Test
    void crashMidProcessing_leavesAnIncompletePublication_thatResubmitReplaysOnRestart(Scenario scenario) throws InterruptedException {
        // Simulate the crash: the publishing transaction already committed
        // (Modulith durably records the publication row first - see
        // AuditEventListener's Javadoc), but the listener's own write blows
        // up before it can finish, as if the app died mid-write.
        doThrow(new RuntimeException("simulated crash mid-processing"))
                .when(auditLogRepository).save(any());

        UserLoggedInEvent event = new UserLoggedInEvent(202L, "grace.dev", 7L);

        scenario.publish(event)
                .andWaitForStateChange(eventPublicationRegistry::findIncompletePublications, incomplete -> !incomplete.isEmpty())
                .andVerify(incomplete -> {
                    assertThat(incomplete).hasSize(1);
                    // The crash means no row was ever written - this is
                    // exactly the gap the durable event_publication row
                    // exists to cover.
                    assertThat(auditLogRepository.findAll()).isEmpty();
                });

        // "Restart": whatever caused the crash is gone now. A real boot's
        // republish-outstanding-events-on-restart does this same call
        // automatically on startup; we call it directly here.
        reset(auditLogRepository);
        incompleteEventPublications.resubmitIncompletePublications(publication -> true);

        List<AuditLog> replayed = awaitAuditLogWrite();
        assertThat(replayed).hasSize(1);
        assertThat(replayed.get(0).getActorUsername()).isEqualTo("grace.dev");
        assertThat(eventPublicationRegistry.findIncompletePublications()).isEmpty();
    }

    private List<AuditLog> awaitAuditLogWrite() throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            List<AuditLog> logs = auditLogRepository.findAll();
            if (!logs.isEmpty()) {
                return logs;
            }
            Thread.sleep(100);
        }
        return auditLogRepository.findAll();
    }
}
