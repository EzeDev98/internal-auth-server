package com.internal.auth.feature.client.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.ClientAlreadyExistsException;
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
 */
@Service
@RequiredArgsConstructor
public class ClientApplicationServiceImpl implements ClientApplicationService {

    private static final Logger log = LoggerFactory.getLogger(ClientApplicationServiceImpl.class);

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
}
