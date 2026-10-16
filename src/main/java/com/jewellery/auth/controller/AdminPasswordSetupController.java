package com.jewellery.auth.controller;

import com.jewellery.auth.entity.Role;
import com.jewellery.auth.entity.User;
import com.jewellery.auth.repository.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/auth/setup")
public class AdminPasswordSetupController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String setupKey;

    public AdminPasswordSetupController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${admin-setup.key:}") String setupKey) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.setupKey = setupKey;
    }

    public record SetupRequest(
            @NotBlank @Email String email,
            @NotBlank @Size(min = 12, max = 72) String newPassword) {
    }

    @PostMapping("/reset-admin-password")
    public String resetAdminPassword(
            @RequestHeader(value = "X-Setup-Key", required = false)
            String suppliedKey,
            @Valid @RequestBody SetupRequest request) {

        if (setupKey.isBlank() || suppliedKey == null ||
                !MessageDigest.isEqual(
                        setupKey.getBytes(StandardCharsets.UTF_8),
                        suppliedKey.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Setup not authorized");
        }

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Admin account not found"));

        if (user.getRole() != Role.ADMIN ||
                !Boolean.TRUE.equals(user.getIsActive())) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Active admin account required");
        }

        user.setPasswordHash(
                passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        return "Admin password updated successfully";
    }
}