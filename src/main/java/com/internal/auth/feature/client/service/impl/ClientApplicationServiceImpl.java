package com.internal.auth.feature.client.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.ClientAlreadyExistsException;
import com.internal.auth.common.exception.InvalidClientCredentialsException;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.client.service.ClientApplicationService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static com.internal.auth.common.constant.AppConstant.CLIENT_SECRET_BYTES;
import static com.internal.auth.common.constant.AppConstant.SECURE_RANDOM;

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
    private static final String INVALID_CLIENT_CREDENTIALS_MESSAGE = "Invalid client credentials";

    private final ClientApplicationRepository clientApplicationRepository;
    private final PasswordEncoder passwordEncoder;

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
        client.setName(name);
        client.setDescription(request.getDescription());
        client.setRedirectUris(nullSafe(request.getRedirectUris()));
        client.setScopes(nullSafe(request.getScopes()));
        client.setGrantTypes(nullSafe(request.getGrantTypes()));
        // enabled defaults to true on the entity itself.

        ClientApplication saved;
        try {
            saved = clientApplicationRepository.save(client);
        } catch (DataIntegrityViolationException e) {
            log.warn("Client application creation lost a uniqueness race at save-time (clientId={})", clientId);
            throw new ClientAlreadyExistsException("A client application with that clientId already exists");
        }

        log.info("New client application registered, id={}, clientId={}", saved.getId(), saved.getClientId());

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
    @Transactional
    public CreateClientApplicationResponse rotateClientSecret(String clientId) {
        ClientApplication client = getEnabledClientByClientId(clientId);

        String rawSecret = generateClientSecret();
        client.setClientSecretHash(passwordEncoder.encode(rawSecret));
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
        String internalAdminClientId = com.internal.auth.common.constant.AppConstant.INTERNAL_ADMIN_CLIENT_ID;

        Optional<ClientApplication> existing = clientApplicationRepository.findByClientId(internalAdminClientId);
        if (existing.isPresent()) {
            return existing.get();
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
        // enabled defaults to true on the entity itself.

        try {
            return clientApplicationRepository.save(client);
        } catch (DataIntegrityViolationException e) {
            // Lost a create-vs-create race against a concurrent first call -
            // same backstop pattern as createClient() above.
            log.warn("Internal admin client application creation lost a uniqueness race at save-time");
            return clientApplicationRepository.findByClientId(internalAdminClientId)
                    .orElseThrow(() -> new BadRequestException("Failed to resolve internal admin client application after a create-vs-create race"));
        }
    }

}
