package com.reused.auth.web;

import com.reused.auth.dto.LoginRequest;
import com.reused.auth.dto.SignupRequest;
import com.reused.auth.service.EmailAuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final EmailAuthService auth;

    public AuthController(EmailAuthService auth) {
        this.auth = auth;
    }

    @PostMapping("/signup")
    public String signup(@RequestBody SignupRequest request) {
        return auth.signup(request);
    }

    @PostMapping("/login")
    public boolean login(@RequestBody LoginRequest request) {
        return auth.login(request, "stored-hash");
    }
}
