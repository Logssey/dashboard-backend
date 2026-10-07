package com.logssey.auth;

import com.logssey.auth.dto.request.LoginRequest;
import com.logssey.auth.dto.response.LoginResponse;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 로그인·로그아웃·내 정보 조회 (API 명세 AUTH) */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final String SESSION_COOKIE_NAME = "JSESSIONID";
    private static final String LOGIN_FAILED_MESSAGE = "아이디 또는 비밀번호가 올바르지 않습니다.";

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final AuthService authService;

    public AuthController(AuthenticationManager authenticationManager,
                          SecurityContextRepository securityContextRepository,
                          AuthService authService) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.authService = authService;
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest loginRequest,
                               HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.loginId(), loginRequest.password()));
        } catch (AuthenticationException e) {
            // 아이디 없음과 비밀번호 틀림을 구분하지 않는다
            throw new ApiException(ErrorCode.UNAUTHENTICATED, LOGIN_FAILED_MESSAGE);
        }

        // 세션 고정 공격 방지: 로그인 전에 쓰던 세션이 있으면 세션 ID를 새로 바꾼다
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        return authService.recordLogin(authentication.getName());
    }

    /** 이미 세션이 끝난 상태여도 204를 돌려준다 */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        Cookie expired = new Cookie(SESSION_COOKIE_NAME, "");
        expired.setPath("/");
        expired.setMaxAge(0);
        expired.setHttpOnly(true);
        response.addCookie(expired);

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public LoginResponse me(Authentication authentication) {
        return authService.getMe(authentication.getName());
    }
}
