package com.internal.auth.config;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Step 14B - echoes the current request's Micrometer Tracing trace ID back
 * as a response header, so a caller (or whoever's looking at a support
 * ticket) can grab it from a response and grep every log line for that
 * request - including 14A's async AuditEventListener write, since Brave's
 * context propagation carries the same trace ID across the @Async boundary
 * @ApplicationModuleListener runs on.
 *
 * Registered as a plain @Component: Spring Boot auto-registers any Filter
 * bean against the servlet container it's defined in. This bean lives in
 * the main application context, so it only ever runs for requests on the
 * main API port (server.port) - never for the separate management port
 * (management.server.port, see application.properties) actuator now runs
 * on, which is a distinct embedded context with none of this context's
 * beans.
 *
 * No explicit @Order is set, on purpose: Spring Boot's own tracing
 * instrumentation (registered once micrometer-tracing-bridge-brave is on
 * the classpath, see pom.xml) runs very early so it wraps everything else.
 * Leaving this filter at the default (lowest-precedence) order guarantees
 * it runs after that instrumentation has already started the current span,
 * so tracer.currentSpan() below is never null for a real request.
 */
@Component
@RequiredArgsConstructor
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final String TRACE_ID_HEADER = "X-Trace-Id";

    private final Tracer tracer;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null) {
            response.setHeader(TRACE_ID_HEADER, currentSpan.context().traceId());
        }
        filterChain.doFilter(request, response);
    }
}
