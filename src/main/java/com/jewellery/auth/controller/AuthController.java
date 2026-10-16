package com.jewellery.auth.controller;

import com.jewellery.auth.dto.LoginRequest;
import com.jewellery.auth.dto.LoginResponse;
import com.jewellery.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.jewellery.auth.dto.AdminRegistrationRequest;
import com.jewellery.auth.dto.AdminRegistrationResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ResponseStatus;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }
    @PostMapping("/register-admin")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    public AdminRegistrationResponse registerAdmin(
            @Valid @RequestBody AdminRegistrationRequest request) {

        return authService.registerAdmin(request);
    }
}