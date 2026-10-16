package com.internal.auth.feature.passwordreset.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.feature.identity.dto.request.ChangePasswordRequest;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.passwordreset.service.PasswordChangeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordChangeServiceImpl implements PasswordChangeService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ResetValidator resetValidator;

    @Override
    @Transactional
    public void changePassword(Long clientApplicationId, ChangePasswordRequest request) {
        User user = userRepository.findByUsernameAndClientApplicationId(request.getUsername().trim(), clientApplicationId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // 400, not 401: a caller reads 401 as "your session is over".
        if (user.getPassword() == null || !passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Incorrect password.");
        }

        // The same rules a reset applies to a new password.
        resetValidator.validateNewPassword(request.getNewPassword(), request.getNewPassword());

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        log.info("Password changed for user id {}", user.getId());
    }
}
