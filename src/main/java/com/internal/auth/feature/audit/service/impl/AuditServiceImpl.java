package com.internal.auth.feature.audit.service.impl;

import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.feature.audit.service.AuditService;
import com.internal.auth.feature.identity.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditServiceImpl implements AuditService {

    private final ApplicationEventPublisher eventPublisher;

    @Override
    public void recordUserLoggedIn(User user, Long clientApplicationId) {
        eventPublisher.publishEvent(new UserLoggedInEvent(user.getId(), user.getUsername(), clientApplicationId));
    }
}
