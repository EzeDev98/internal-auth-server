package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.identity.dto.request.RegisterRequest;
import com.internal.auth.feature.identity.dto.response.RegisterResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import com.internal.auth.feature.identity.service.PhoneVerificationService;
import com.internal.auth.feature.identity.service.UserRegistrationService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import com.internal.auth.feature.rbac.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.UUID;

/** Registers users and triggers their verification. */
@Service
@Slf4j
@RequiredArgsConstructor
public class UserRegistrationServiceImpl implements UserRegistrationService {

    private final UserRepository userRepository;
    private final RegistrationValidator registrationValidator;
    private final ResetValidator resetValidator;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final PhoneVerificationService phoneVerificationService;
    private final UserService userService;

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request, Long clientApplicationId) {
        registrationValidator.validateUsername(request.getUsername());
        registrationValidator.validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());
        registrationValidator.validatePhoneNumberIfPresent(request.getPhoneNumber());
        registrationValidator.validateEmailIfPresent(request.getEmail());

        resetValidator.validateNewPassword(request.getPassword(), request.getConfirmPassword());

        String username = request.getUsername().trim();
        if (userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Username or password is incorrect");
        }

        String phoneNumber = normalize(request.getPhoneNumber());
        if (phoneNumber != null && userRepository.findByPhoneNumberAndClientApplicationId(phoneNumber, clientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Phone number or password is incorrect");
        }

        String email = normalize(request.getEmail());
        if (email != null && userRepository.findByEmailAndClientApplicationId(email, clientApplicationId).isPresent()) {
            throw new UserAlreadyExistsException("Email or password is incorrect");
        }

        User user = new User();
        user.setClientApplicationId(clientApplicationId);
        user.setUsername(username);
        user.setPhoneNumber(phoneNumber);
        user.setEmail(email);
        user.setInternalAuthUserId("IA_" + UUID.randomUUID());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        User savedUser;
        try {
            savedUser = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            log.warn("Registration lost a uniqueness race at save-time (username={})", username);
            throw new UserAlreadyExistsException("Unable to create account with the provided details");
        }

        emailVerificationService.sendVerificationEmail(savedUser);

        phoneVerificationService.sendVerificationOtp(savedUser);

        log.info("New user registered, id={}", savedUser.getId());

        return new RegisterResponse(savedUser.getInternalAuthUserId(), savedUser.getUsername(), "Account created successfully.");
    }

    private String normalize(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
