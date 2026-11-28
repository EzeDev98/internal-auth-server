package com.internal.auth.feature.client.service;

import com.internal.auth.feature.client.dto.ClientApplicationDetailResponse;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;
import com.internal.auth.feature.client.dto.PagedClientApplicationsResponse;
import com.internal.auth.feature.client.dto.UpdateClientApplicationRequest;
import com.internal.auth.feature.client.enums.ClientType;
import com.internal.auth.feature.client.model.ClientApplication;
import org.springframework.data.domain.Pageable;

import java.util.Map;
import java.util.Set;

/** Operations for managing client applications. */
public interface ClientApplicationService {

    CreateClientApplicationResponse createClient(CreateClientApplicationRequest request);

    boolean verifyClientSecret(String clientId, String rawSecret);

    ClientApplication authenticateClient(String clientId, String rawSecret);

    ClientApplication authenticateClientFromBasicAuthHeader(String authorizationHeader);

    ClientApplication getEnabledClientByClientId(String clientId);

    ClientApplication getById(Long id);

    Map<Long, String> getClientIdsByIds(Set<Long> ids);

    CreateClientApplicationResponse rotateClientSecret(String clientId);
    ClientApplication getOrCreateInternalAdminClient();

    PagedClientApplicationsResponse listClients(Boolean enabled, ClientType type, Pageable pageable);

    ClientApplicationDetailResponse getClientDetail(String clientId);

    ClientApplicationDetailResponse updateClient(String clientId, UpdateClientApplicationRequest request);

}
