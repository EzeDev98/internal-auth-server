package com.internal.auth.feature.client.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.ClientAlreadyExistsException;
import com.internal.auth.common.exception.InvalidClientCredentialsException;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.feature.audit.event.ClientSettingsChangedEvent;
import com.internal.auth.common.util.SecretEncryptionService;
import com.internal.auth.feature.client.dto.ClientApplicationDetailResponse;
import com.internal.auth.feature.client.dto.ClientApplicationSummaryResponse;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;
import com.internal.auth.feature.client.dto.PagedClientApplicationsResponse;
import com.internal.auth.feature.client.dto.UpdateClientApplicationRequest;
import com.internal.auth.feature.client.enums.ClientType;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.client.service.ClientApplicationService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.internal.auth.common.constant.AppConstant.*;

/**
 * Step 10D. Admin-only client application registration - not the OAuth2
 * client-credentials grant itself (that's Step 12, once Spring Authorization
 * Server's RegisteredClientRepository is wired up), just the data-layer
 * piece: create a ClientApplication row with a server-generated secret,
 * store only its BCrypt hash (per Step 9's credential storage policy -
 * client secrets are verified against an already-located row, same as
 * User.password, so BCrypt applies here rather than TokenHasher), and
 * expose a verify method Step 12 can call once the token endpoint exists.
 *
 * Same uniqueness-race defense as RegistrationServiceImpl (Step 10B):
 * findByClientId is check-then-act, so save() is wrapped to catch
 * DataIntegrityViolationException as a backstop against client_applications'
 * uk_client_applications_client_id constraint.
 *
 * rotateClientSecret (fixes "no client-secret rotation endpoint") reuses
 * the exact same generateClientSecret()/BCrypt-encode logic createClient
 * uses, just against an already-existing row instead of a new one -
 * deliberately no dual-valid grace period like SigningKeyService's key
 * rotation has: a client secret used over HTTP Basic isn't embedded in
 * already-issued tokens the way a signing key is, so there's nothing
 * still in flight that a grace period would protect, and the scenario
 * this fixes ("I lost the secret") has no old secret worth keeping valid
 * anyway.
 */
@Service
@RequiredArgsConstructor
public class ClientApplicationServiceImpl implements ClientApplicationService {

    private static final Logger log = LoggerFactory.getLogger(ClientApplicationServiceImpl.class);
    private static final String BASIC_PREFIX = "Basic ";
    private static final int MIN_REFRESH_TOKEN_TTL_DAYS = 1;
    private static final int MAX_REFRESH_TOKEN_TTL_DAYS = 365;
    private static final int MAX_SESSION_LIFETIME_DAYS = 3650;
    private static final Set<String> ALLOWED_GRANT_TYPES = Set.of("authorization_code", "refresh_token", "client_credentials");
    private static final String INVALID_CLIENT_CREDENTIALS_MESSAGE = "Invalid client credentials";

    private final ClientApplicationRepository clientApplicationRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecretEncryptionService secretEncryptionService;
    private final ApplicationEventPublisher eventPublisher;
    private final AuthenticationHelper authenticationHelper;

    @Override
    @Transactional
    public CreateClientApplicationResponse createClient(CreateClientApplicationRequest request) {
        String clientId = require(request.getClientId(), "clientId is required");
        String name = require(request.getName(), "name is required");

        if (clientApplicationRepository.findByClientId(clientId).isPresent()) {
            throw new ClientAlreadyExistsException("A client application with that clientId already exists");
        }

        String rawSecret = generateClientSecret();

        ClientApplication client = new ClientApplication();
        client.setClientId(clientId);
        client.setClientSecretHash(passwordEncoder.encode(rawSecret));
        client.setClientSecretEncrypted(secretEncryptionService.encrypt(rawSecret));
        client.setName(name);
        client.setDescription(request.getDescription());
        client.setRedirectUris(nullSafe(request.getRedirectUris()));
        client.setScopes(nullSafe(request.getScopes()));
        client.setGrantTypes(nullSafe(request.getGrantTypes()));
        applyRefreshTokenSettings(client, request.getRefreshTokenRotationEnabled(), request.getRefreshTokenTtlDays(), request.getRefreshTokenMaxLifetimeDays());
        client.setRevokePriorSessionsOnLogin(request.getRevokePriorSessionsOnLogin() == null || request.getRevokePriorSessionsOnLogin());
        // enabled defaults to true on the entity itself.

        ClientApplication saved;
        try {
            saved = clientApplicationRepository.save(client);
        } catch (DataIntegrityViolationException e) {
            log.warn("Client application creation lost a uniqueness race at save-time (clientId={})", clientId);
            throw new ClientAlreadyExistsException("A client application with that clientId already exists");
        }

        log.info("New client application registered, id={}, clientId={}", saved.getId(), saved.getClientId());
        publishSessionSettingsAudit(saved, null);

        return new CreateClientApplicationResponse(
                saved.getId(),
                saved.getClientId(),
                rawSecret,
                saved.getName(),
                "Save this client secret now - it will not be shown again."
        );
    }

    @Override
    public boolean verifyClientSecret(String clientId, String rawSecret) {
        if (clientId == null || rawSecret == null) {
            return false;
        }
        Optional<ClientApplication> clientOptional = clientApplicationRepository.findByClientId(clientId);
        if (clientOptional.isEmpty()) {
            return false;
        }
        ClientApplication client = clientOptional.get();
        if (!client.isEnabled() || client.getClientSecretHash() == null) {
            return false;
        }
        return passwordEncoder.matches(rawSecret, client.getClientSecretHash());
    }

    @Override
    public ClientApplication authenticateClient(String clientId, String rawSecret) {
        if (clientId == null || rawSecret == null) {
            throw new InvalidClientCredentialsException(INVALID_CLIENT_CREDENTIALS_MESSAGE);
        }
        ClientApplication client = clientApplicationRepository.findByClientId(clientId)
                .orElseThrow(() -> new InvalidClientCredentialsException(INVALID_CLIENT_CREDENTIALS_MESSAGE));
        if (!client.isEnabled() || client.getClientSecretHash() == null
                || !passwordEncoder.matches(rawSecret, client.getClientSecretHash())) {
            throw new InvalidClientCredentialsException(INVALID_CLIENT_CREDENTIALS_MESSAGE);
        }
        return client;
    }

    @Override
    public ClientApplication authenticateClientFromBasicAuthHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            throw new InvalidClientCredentialsException(INVALID_CLIENT_CREDENTIALS_MESSAGE);
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(authorizationHeader.substring(BASIC_PREFIX.length()).trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new InvalidClientCredentialsException(INVALID_CLIENT_CREDENTIALS_MESSAGE);
        }
        int colonIndex = decoded.indexOf(':');
        if (colonIndex < 0) {
            throw new InvalidClientCredentialsException(INVALID_CLIENT_CREDENTIALS_MESSAGE);
        }
        return authenticateClient(decoded.substring(0, colonIndex), decoded.substring(colonIndex + 1));
    }

    @Override
    public ClientApplication getEnabledClientByClientId(String clientId) {
        ClientApplication client = clientApplicationRepository.findByClientId(clientId)
                .orElseThrow(() -> new BadRequestException("Unknown clientId"));
        if (!client.isEnabled()) {
            throw new BadRequestException("Unknown clientId");
        }
        return client;
    }

    @Override
    public ClientApplication getById(Long id) {
        return clientApplicationRepository.findById(id)
                .orElseThrow(() -> new BadRequestException("Unknown client application"));
    }

    @Override
    public Map<Long, String> getClientIdsByIds(Set<Long> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }
        return clientApplicationRepository.findAllById(ids).stream()
                .collect(Collectors.toMap(ClientApplication::getId, ClientApplication::getClientId));
    }

    @Override
    @Transactional
    public CreateClientApplicationResponse rotateClientSecret(String clientId) {
        ClientApplication client = getEnabledClientByClientId(clientId);

        String rawSecret = generateClientSecret();
        client.setClientSecretHash(passwordEncoder.encode(rawSecret));
        client.setClientSecretEncrypted(secretEncryptionService.encrypt(rawSecret));
        ClientApplication saved = clientApplicationRepository.save(client);

        log.info("Client secret rotated for client application id={}, clientId={}", saved.getId(), saved.getClientId());

        return new CreateClientApplicationResponse(
                saved.getId(),
                saved.getClientId(),
                rawSecret,
                saved.getName(),
                "Save this client secret now - it will not be shown again. The previous secret no longer works."
        );
    }

    private String generateClientSecret() {
        byte[] bytes = new byte[CLIENT_SECRET_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private Set<String> nullSafe(Set<String> values) {
        return values == null ? new HashSet<>() : new HashSet<>(values);
    }

    private String require(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new BadRequestException(message);
        }
        return value.trim();
    }

    @Override
    @Transactional
    public ClientApplication getOrCreateInternalAdminClient() {
        String internalAdminClientId = INTERNAL_ADMIN_CLIENT_ID;

        Optional<ClientApplication> existing = clientApplicationRepository.findByClientId(internalAdminClientId);
        if (existing.isPresent()) {
            return ensureRefreshTokenGrant(existing.get());
        }

        ClientApplication client = new ClientApplication();
        client.setClientId(internalAdminClientId);
        // No secret on purpose - a public/no-secret client (see class
        // javadoc on ClientApplication.clientSecretHash). Nothing ever
        // authenticates against this row via HTTP Basic; AdminController
        // resolves it by clientId only.
        client.setClientSecretHash(null);
        client.setName("Internal Auth Admin Console");
        client.setDescription("Reserved client application internal-auth-server's own admin accounts are grouped under. Not a real integrating app - never authenticated against via HTTP Basic.");
        client.setGrantTypes(new HashSet<>(Set.of("client_credentials", "refresh_token")));
        // enabled defaults to true on the entity itself.

        try {
            return clientApplicationRepository.save(client);
        } catch (DataIntegrityViolationException e) {
            // Lost a create-vs-create race against a concurrent first call -
            // same backstop pattern as createClient() above.
            log.warn("Internal admin client application creation lost a uniqueness race at save-time");
            return ensureRefreshTokenGrant(clientApplicationRepository.findByClientId(internalAdminClientId)
                    .orElseThrow(() -> new BadRequestException("Failed to resolve internal admin client application after a create-vs-create race")));
        }
    }

    /**
     * Step 2H self-heal: a row created before this pass has an empty
     * grantTypes set, so admin login never minted a refresh token. Backfills
     * it on every read instead of requiring a migration, so an
     * already-provisioned environment picks this up with no manual step.
     */
    private ClientApplication ensureRefreshTokenGrant(ClientApplication client) {
        if (client.getGrantTypes().contains("refresh_token")) {
            return client;
        }
        Set<String> grantTypes = new HashSet<>(client.getGrantTypes());
        grantTypes.add("client_credentials");
        grantTypes.add("refresh_token");
        client.setGrantTypes(grantTypes);
        return clientApplicationRepository.save(client);
    }

    @Override
    @Transactional(readOnly = true)
    public PagedClientApplicationsResponse listClients(Boolean enabled, ClientType type, Pageable pageable) {
        Boolean publicOnly = type == null ? null : type == ClientType.PUBLIC;
        Page<ClientApplication> page = clientApplicationRepository.searchForAdmin(enabled, publicOnly, pageable);
        List<ClientApplicationSummaryResponse> content = page.getContent().stream()
                .map(this::toSummary)
                .toList();
        return new PagedClientApplicationsResponse(content, page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages());
    }

    @Override
    @Transactional(readOnly = true)
    public ClientApplicationDetailResponse getClientDetail(String clientId) {
        ClientApplication client = clientApplicationRepository.findByClientId(clientId)
                .orElseThrow(() -> new BadRequestException("Unknown client application"));
        return toDetail(client);
    }

    @Override
    @Transactional
    public ClientApplicationDetailResponse updateClient(String clientId, UpdateClientApplicationRequest request) {
        ClientApplication client = clientApplicationRepository.findByClientId(clientId)
                .orElseThrow(() -> new BadRequestException("Unknown client application"));

        String settingsBefore = sessionSettingsSnapshot(client);

        if (request.getName() != null) {
            client.setName(require(request.getName(), "name cannot be blank"));
        }
        if (request.getDescription() != null) {
            client.setDescription(request.getDescription());
        }
        if (request.getRedirectUris() != null) {
            client.setRedirectUris(new HashSet<>(request.getRedirectUris()));
        }
        if (request.getScopes() != null) {
            client.setScopes(new HashSet<>(request.getScopes()));
        }
        if (request.getEnabled() != null) {
            client.setEnabled(request.getEnabled());
        }
        if (request.getGrantTypes() != null) {
            client.setGrantTypes(validateGrantTypes(request.getGrantTypes()));
        }
        applyRefreshTokenSettings(client, request.getRefreshTokenRotationEnabled(), request.getRefreshTokenTtlDays(), request.getRefreshTokenMaxLifetimeDays());
        if (!client.isRefreshTokenRotationEnabled() && !client.getGrantTypes().contains("refresh_token")) {
            throw new BadRequestException("Turn off the persistent refresh token before removing the refresh_token grant type");
        }
        if (request.getRevokePriorSessionsOnLogin() != null) {
            client.setRevokePriorSessionsOnLogin(request.getRevokePriorSessionsOnLogin());
        }

        ClientApplication saved = clientApplicationRepository.save(client);
        log.info("Client application updated, id={}, clientId={}", saved.getId(), saved.getClientId());
        publishSessionSettingsAudit(saved, settingsBefore);
        return toDetail(saved);
    }

    /**
     * Persistent (non-rotating) refresh token settings. Both arguments null
     * means "leave as is". Rotation on always clears the per-client TTL
     * (a single-use token has no use for one); rotation off requires an
     * explicit TTL and the refresh_token grant, since without that grant
     * UserLoginServiceImpl never mints a refresh token at all.
     */
    private void applyRefreshTokenSettings(ClientApplication client, Boolean rotationEnabled, Integer ttlDays, Integer maxLifetimeDays) {
        if (rotationEnabled == null && ttlDays == null && maxLifetimeDays == null) {
            return;
        }
        boolean rotation = rotationEnabled != null ? rotationEnabled : client.isRefreshTokenRotationEnabled();
        Integer ttl = ttlDays != null ? ttlDays : client.getRefreshTokenTtlDays();
        // When rotationEnabled is supplied, the persistent settings are replaced as a set, so a
        // null maxLifetimeDays clears the cap. Otherwise a null leaves the existing cap alone.
        Integer maxLifetime = (rotationEnabled != null || maxLifetimeDays != null)
                ? maxLifetimeDays
                : client.getRefreshTokenMaxLifetimeDays();

        if (rotation) {
            if (ttlDays != null || maxLifetimeDays != null) {
                throw new BadRequestException("refreshTokenTtlDays and refreshTokenMaxLifetimeDays only apply when refreshTokenRotationEnabled is false");
            }
            client.setRefreshTokenRotationEnabled(true);
            client.setRefreshTokenTtlDays(null);
            client.setRefreshTokenMaxLifetimeDays(null);
            return;
        }

        if (ttl == null) {
            throw new BadRequestException("refreshTokenTtlDays is required when refreshTokenRotationEnabled is false");
        }
        if (ttl < MIN_REFRESH_TOKEN_TTL_DAYS || ttl > MAX_REFRESH_TOKEN_TTL_DAYS) {
            throw new BadRequestException("refreshTokenTtlDays must be between " + MIN_REFRESH_TOKEN_TTL_DAYS + " and " + MAX_REFRESH_TOKEN_TTL_DAYS);
        }
        if (!client.getGrantTypes().contains("refresh_token")) {
            throw new BadRequestException("A persistent refresh token requires the client to have the refresh_token grant type");
        }

        if (maxLifetime != null && (maxLifetime < ttl || maxLifetime > MAX_SESSION_LIFETIME_DAYS)) {
            throw new BadRequestException("refreshTokenMaxLifetimeDays must be between refreshTokenTtlDays (" + ttl + ") and " + MAX_SESSION_LIFETIME_DAYS);
        }

        boolean changed = client.isRefreshTokenRotationEnabled()
                || !ttl.equals(client.getRefreshTokenTtlDays())
                || !java.util.Objects.equals(maxLifetime, client.getRefreshTokenMaxLifetimeDays());
        client.setRefreshTokenRotationEnabled(false);
        client.setRefreshTokenTtlDays(ttl);
        client.setRefreshTokenMaxLifetimeDays(maxLifetime);
        if (changed) {
            log.info("Client application {} persistent refresh tokens: ttlDays={}, maxLifetimeDays={}", client.getClientId(), ttl, maxLifetime);
        }
    }

    /**
     * Grant types can be edited on a live client, with three rules: at least one must remain (an empty set would silently fall back to
     * client_credentials), only the three supported values are accepted, and refresh_token cannot be removed from a client that still has
     * persistent refresh tokens on. Tokens already issued are not revoked by removing a grant type.
     */
    private Set<String> validateGrantTypes(Set<String> requested) {
        if (requested.isEmpty()) {
            throw new BadRequestException("At least one grant type is required");
        }
        for (String grantType : requested) {
            if (!ALLOWED_GRANT_TYPES.contains(grantType)) {
                throw new BadRequestException("Unsupported grant type: " + grantType);
            }
        }
        return new HashSet<>(requested);
    }

    private String sessionSettingsSnapshot(ClientApplication client) {
        return "rotationEnabled=" + client.isRefreshTokenRotationEnabled()
                + ", refreshTokenTtlDays=" + client.getRefreshTokenTtlDays()
                + ", refreshTokenMaxLifetimeDays=" + client.getRefreshTokenMaxLifetimeDays()
                + ", revokePriorSessionsOnLogin=" + client.isRevokePriorSessionsOnLogin()
                + ", grantTypes=" + new java.util.TreeSet<>(client.getGrantTypes());
    }

    /** before == null means the client was just created. Publishes nothing when an update changed none of these settings. */
    private void publishSessionSettingsAudit(ClientApplication saved, String before) {
        String after = sessionSettingsSnapshot(saved);
        if (before != null && before.equals(after)) {
            return;
        }
        String description = before == null
                ? "Client " + saved.getClientId() + " created with " + after
                : "Client " + saved.getClientId() + " session settings changed from [" + before + "] to [" + after + "]";
        eventPublisher.publishEvent(new ClientSettingsChangedEvent(authenticationHelper.getCurrentUsername(), saved.getId(), description));
    }

    private ClientApplicationSummaryResponse toSummary(ClientApplication client) {
        return new ClientApplicationSummaryResponse(
                client.getId(),
                client.getClientId(),
                client.getName(),
                client.getClientSecretHash() == null ? ClientType.PUBLIC : ClientType.CONFIDENTIAL,
                client.isEnabled(),
                client.getCreatedAt());
    }

    private ClientApplicationDetailResponse toDetail(ClientApplication client) {
        return new ClientApplicationDetailResponse(
                client.getId(),
                client.getClientId(),
                client.getName(),
                client.getDescription(),
                client.getRedirectUris(),
                client.getScopes(),
                client.getGrantTypes(),
                client.getClientSecretHash() == null ? ClientType.PUBLIC : ClientType.CONFIDENTIAL,
                client.isEnabled(),
                client.getCreatedAt(),
                client.getUpdatedAt(),
                decryptSecretForDisplay(client),
                client.isRefreshTokenRotationEnabled(),
                client.getRefreshTokenTtlDays(),
                client.getRefreshTokenMaxLifetimeDays(),
                client.isRevokePriorSessionsOnLogin());
    }

    // Admin-console-only reveal: decrypts clientSecretEncrypted purely for
    // display, never for authentication (see ClientApplication's javadoc on
    // that field). Null for PUBLIC clients and for any CONFIDENTIAL client
    // that predates this column - regenerate is the only way for those to
    // get a viewable secret.
    private String decryptSecretForDisplay(ClientApplication client) {
        if (client.getClientSecretEncrypted() == null) {
            return null;
        }
        return secretEncryptionService.decrypt(client.getClientSecretEncrypted());
    }

}
