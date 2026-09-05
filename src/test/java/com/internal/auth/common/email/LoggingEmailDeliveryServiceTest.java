package com.internal.auth.common.email;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 16B: locks in today's behavior around app.email.log-to-console -
 * confirmed OFF by default, confirmed to genuinely gate whether the raw
 * verification link reaches the log, so a future change to that default
 * (a real security-relevant regression: this app's own Javadoc says the
 * flag "must stay false in production") doesn't go unnoticed.
 *
 * <p>No Spring context needed - LoggingEmailDeliveryService has exactly
 * one collaborator (SLF4J's Logger) and one @Value field, same pattern as
 * Step 16A's ContiguityOtpDeliveryServiceTest. The default itself is
 * asserted two ways: directly off the @Value annotation's literal (so
 * editing "${app.email.log-to-console:false}" to any other default fails
 * this test immediately, without needing a Spring context to bind it),
 * and behaviorally, by constructing the service via `new` (leaving the
 * boolean field at Java's own uninitialized default, exactly mirroring
 * matchIfMissing behavior with no property set at all) and asserting the
 * link never reaches the logger.
 */
class LoggingEmailDeliveryServiceTest {

    private static final String EMAIL = "user@example.com";
    private static final String VERIFICATION_LINK = "https://app.example.com/activate?token=super-secret-raw-token";

    private LoggingEmailDeliveryService service;
    private ListAppender<ILoggingEvent> logAppender;
    private ch.qos.logback.classic.Logger logbackLogger;

    @BeforeEach
    void setUp() {
        service = new LoggingEmailDeliveryService();

        logbackLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(LoggingEmailDeliveryService.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        logbackLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        logbackLogger.detachAppender(logAppender);
        logAppender.stop();
    }

    @Test
    void logToConsoleDefaultsToFalse_asDeclaredOnTheValueAnnotationItself() throws NoSuchFieldException {
        Field field = LoggingEmailDeliveryService.class.getDeclaredField("logToConsole");
        Value valueAnnotation = field.getAnnotation(Value.class);

        assertThat(valueAnnotation)
                .as("logToConsole must stay backed by app.email.log-to-console")
                .isNotNull();
        assertThat(valueAnnotation.value())
                .as("the property's own default must stay 'false' - this app's Javadoc requires it stay false in production")
                .isEqualTo("${app.email.log-to-console:false}");
    }

    @Test
    void sendVerificationEmail_neverLogsTheRawLink_whenLogToConsoleIsAtItsDefault() {
        // No ReflectionTestUtils.setField call here on purpose - an
        // un-set boolean field defaults to false in plain Java exactly
        // like matchIfMissing does when the property itself is absent,
        // so this genuinely exercises "the default", not just "false".
        service.sendVerificationEmail(EMAIL, VERIFICATION_LINK);

        assertThat(logAppender.list).hasSize(1);
        ILoggingEvent event = logAppender.list.get(0);

        assertThat(event.getLevel()).isEqualTo(Level.INFO);
        assertThat(event.getFormattedMessage())
                .contains(EMAIL)
                .doesNotContain(VERIFICATION_LINK)
                .doesNotContain("[DEV ONLY]")
                .isEqualTo("Email verification link generated for " + EMAIL + " (delivery provider not configured)");
    }

    @Test
    void sendVerificationEmail_logsTheRawLink_onlyWhenLogToConsoleIsExplicitlyEnabled() {
        ReflectionTestUtils.setField(service, "logToConsole", true);

        service.sendVerificationEmail(EMAIL, VERIFICATION_LINK);

        assertThat(logAppender.list).hasSize(1);
        ILoggingEvent event = logAppender.list.get(0);

        assertThat(event.getLevel()).isEqualTo(Level.INFO);
        assertThat(event.getFormattedMessage())
                .contains("[DEV ONLY]")
                .contains(EMAIL)
                .contains(VERIFICATION_LINK);
    }
}
