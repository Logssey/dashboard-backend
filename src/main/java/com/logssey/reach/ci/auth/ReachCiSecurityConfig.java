package com.logssey.reach.ci.auth;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import com.logssey.common.error.ApiErrorResponse;
import com.logssey.common.error.ErrorCode;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Reach CI 인증 (GitHub OIDC, API 명세 2-2, 11/02 결정 ①②③). 기존 SecurityConfig 는 그대로 둔다.
 *
 * - 이 체인은 Bearer 헤더가 있는 /api/v1/reach/** 요청만 받는다. Bearer 가 없으면 기존 체인(대시보드 세션)이 받는다
 * - 토큰 검증 실패(서명, 발급자, 만료, aud, 필요한 클레임) → 401. 유효한 토큰으로 /api/v1/reach/ci/** 밖 → 403
 * - 세션·CSRF 를 쓰지 않는다(쿠키가 아니라 헤더로 인증)
 * - 토큰 디코더는 이 체인 안에서만 쓴다(Bean 으로 내놓지 않아 다른 모듈에 영향이 없다)
 */
@Configuration
@EnableConfigurationProperties(ReachCiProperties.class)
class ReachCiSecurityConfig {

    static final String AUTHORITY = "REACH_CI";

    /** V34 reach_scans.requested_by_repository·requested_by_subject 칸 길이 */
    private static final int REPOSITORY_MAX = 200;
    private static final int SUBJECT_MAX = 300;

    @Bean
    @Order(2)
    SecurityFilterChain reachCiSecurityFilterChain(HttpSecurity http, ReachCiProperties properties) throws Exception {
        RequestMatcher reach = PathPatternRequestMatcher.withDefaults().matcher("/api/v1/reach/**");
        RequestMatcher bearer = request -> {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            return header != null && header.regionMatches(true, 0, "Bearer ", 0, 7);
        };

        http.securityMatcher(new AndRequestMatcher(reach, bearer))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/reach/ci/**").hasAuthority(AUTHORITY)
                        .anyRequest().denyAll())
                .oauth2ResourceServer(server -> server
                        .jwt(jwt -> jwt.decoder(decoder(properties.oidc())).jwtAuthenticationConverter(converter()))
                        .authenticationEntryPoint(unauthenticated())
                        .accessDeniedHandler(forbidden()))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(unauthenticated())
                        .accessDeniedHandler(forbidden()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }

    /** 서명은 발급자의 공개 키(JWKS, 첫 토큰 때 받아 캐시), 그다음 발급자·만료·aud·필요한 클레임 (②) */
    static JwtDecoder decoder(ReachCiProperties.Oidc oidc) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oidc.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(oidc.issuer()),
                new JwtClaimValidator<Object>(JwtClaimNames.AUD, aud -> audienceContains(aud, oidc.audience())),
                ReachCiSecurityConfig::requiredClaims));
        return decoder;
    }

    private static boolean audienceContains(Object aud, String expected) {
        if (aud instanceof Collection<?> values) return values.contains(expected);
        return expected.equals(aud);
    }

    /** 권한 판단(ReachCiAccess)과 스캔 기록(V34)에 쓰는 클레임 */
    private static OAuth2TokenValidatorResult requiredClaims(Jwt jwt) {
        String repository = jwt.getClaimAsString("repository");
        String subject = jwt.getSubject();
        boolean ok = repository != null && repository.indexOf('/') > 0 && repository.length() <= REPOSITORY_MAX
                && subject != null && !subject.isBlank() && subject.length() <= SUBJECT_MAX
                && notBlank(jwt.getClaimAsString("event_name")) && notBlank(jwt.getClaimAsString("ref"));
        return ok ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Missing GitHub OIDC claims", null));
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private static JwtAuthenticationConverter converter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> List.of(new SimpleGrantedAuthority(AUTHORITY)));
        return converter;
    }

    /** 공통 오류 모양 { code, message } (security.JsonSecurityErrorHandlers 와 같다. 그쪽은 패키지 밖에서 못 써서 따로 둔다) */
    private static AuthenticationEntryPoint unauthenticated() {
        return (request, response, exception) -> write(response, ErrorCode.UNAUTHENTICATED);
    }

    private static AccessDeniedHandler forbidden() {
        return (request, response, exception) -> write(response, ErrorCode.FORBIDDEN);
    }

    private static void write(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setStatus(errorCode.status().value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(ApiErrorResponse.of(errorCode).toJson());
    }
}
