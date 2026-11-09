package com.reused.auth.service;

import com.reused.auth.dto.LoginRequest;
import com.reused.auth.dto.SignupRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class EmailAuthService {
    private final PasswordEncoder passwordEncoder;

    public EmailAuthService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public String signup(SignupRequest request) {
        return passwordEncoder.encode(request.password());
    }

    public boolean login(LoginRequest request, String storedHash) {
        return passwordEncoder.matches(request.password(), storedHash);
    }
}
