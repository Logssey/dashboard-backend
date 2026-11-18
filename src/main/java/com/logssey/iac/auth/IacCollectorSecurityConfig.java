package com.logssey.iac.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import com.logssey.common.error.ApiErrorResponse;
import com.logssey.common.error.ErrorCode;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * IaC 수집기(대시보드 호스트의 매일 Cartography 작업)가 수집 결과를 기록할 때의 인증 (IaC 보안 ADR-13).
 * 기존 SecurityConfig 는 그대로 둔다 (Reach 의 ReachTokenSecurityConfig 와 같은 방식).
 *
 * - 이 체인은 X-IaC-Collector-Token 헤더가 있는 POST /api/v1/iac/jobs/collect-graph/runs 만 받는다.
 *   헤더가 없으면 기존 체인(대시보드 관리자 세션)이 받는다
 * - 토큰은 호스트 비밀 파일(logssey.iac.collector-token, configtree)과 상수 시간으로 비교한다.
 *   설정이 없거나 32자보다 짧으면 모든 토큰을 거부한다 (설치 전에는 닫혀 있다)
 * - 수집기는 호스트 안에서만 부른다 (127.0.0.1:8088). 세션·CSRF 를 쓰지 않는다
 */
@Configuration
public class IacCollectorSecurityConfig {

    static final String HEADER = "X-IaC-Collector-Token";
    public static final String AUTHORITY = "IAC_COLLECTOR";
    static final String PATH = "/api/v1/iac/jobs/collect-graph/runs";
    private static final int MIN_TOKEN_LENGTH = 32;

    @Bean
    @Order(3)
    SecurityFilterChain iacCollectorSecurityFilterChain(HttpSecurity http,
                                                        @Value("${logssey.iac.collector-token:}") String token) throws Exception {
        RequestMatcher path = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, PATH);
        RequestMatcher header = request -> request.getHeader(HEADER) != null;
        http.securityMatcher(new AndRequestMatcher(path, header))
                .addFilterBefore(new CollectorTokenFilter(token), AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority(AUTHORITY))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, e) -> write(response, ErrorCode.UNAUTHENTICATED))
                        .accessDeniedHandler((request, response, e) -> write(response, ErrorCode.FORBIDDEN)))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }

    /** 맞는 토큰이면 수집기 권한을 준다. 틀리면 401 로 끝낸다. */
    static final class CollectorTokenFilter extends OncePerRequestFilter {

        private final byte[] expected;

        CollectorTokenFilter(String token) {
            this.expected = token == null ? new byte[0] : token.strip().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String supplied = request.getHeader(HEADER);
            boolean valid = expected.length >= MIN_TOKEN_LENGTH && supplied != null
                    && MessageDigest.isEqual(expected, supplied.getBytes(StandardCharsets.UTF_8));
            if (!valid) {
                write(response, ErrorCode.UNAUTHENTICATED);
                return;
            }
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "iac-collector", null, List.of(new SimpleGrantedAuthority(AUTHORITY))));
            SecurityContextHolder.setContext(context);
            try {
                chain.doFilter(request, response);
            } finally {
                SecurityContextHolder.clearContext();
            }
        }
    }

    private static void write(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setStatus(errorCode.status().value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(ApiErrorResponse.of(errorCode).toJson());
    }
}
