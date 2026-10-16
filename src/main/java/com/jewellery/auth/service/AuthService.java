package com.jewellery.auth.service;

import com.jewellery.auth.dto.LoginRequest;
import com.jewellery.auth.dto.LoginResponse;
import com.jewellery.auth.entity.User;
import com.jewellery.auth.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.jewellery.auth.dto.AdminRegistrationRequest;
import com.jewellery.auth.dto.AdminRegistrationResponse;
import com.jewellery.auth.entity.Role;
import com.jewellery.auth.entity.User;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public LoginResponse login(LoginRequest request) {

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(this::invalidCredentials);

        if (!Boolean.TRUE.equals(user.getIsActive())) {
            throw invalidCredentials();
        }

        if (!passwordEncoder.matches(
                request.password(), user.getPasswordHash())) {
            throw invalidCredentials();
        }

        String token = jwtService.generateToken(user);

        return new LoginResponse(token);
    }

    private ResponseStatusException invalidCredentials() {
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Invalid email or password"
        );
    }

    @Transactional
    public AdminRegistrationResponse registerAdmin(
            AdminRegistrationRequest request) {

        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Email is already registered"
            );
        }

        User user = new User();
        user.setFullName(request.fullName());
        user.setEmail(request.email());
        user.setPasswordHash(
                passwordEncoder.encode(request.password())
        );
        user.setPhone(request.phone());
        user.setRole(Role.ADMIN);
        user.setIsActive(true);

        userRepository.save(user);

        return new AdminRegistrationResponse(
                "Admin registered successfully",
                user.getEmail()
        );
    }
}