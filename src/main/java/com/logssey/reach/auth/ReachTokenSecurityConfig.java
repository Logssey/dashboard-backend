package com.logssey.reach.auth;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiErrorResponse;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ci.auth.ReachCiProperties;
import com.logssey.reach.l1.ReachL1CollectorProperties;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
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
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Reach 를 부르는 기계(사람이 아닌 호출)의 Bearer 토큰 인증. 기존 SecurityConfig 는 그대로 둔다.
 *
 * - 이 체인은 Bearer 헤더가 있는 /api/v1/reach/** 요청만 받는다. Bearer 가 없으면 기존 체인(대시보드 세션)이 받는다
 * - 토큰의 발급자(iss)로 검증기를 고른다
 *   - GitHub Actions OIDC → CI (API 명세 2-2, 11/02 결정 ①②③): /api/v1/reach/ci/**
 *   - 클러스터 서비스 계정 → L1 수집기: PUT /api/v1/reach/l1/workloads, 수집기 서비스 계정(sub)만
 * - 모르는 발급자, 서명·만료·aud·필요한 클레임이 틀리면 401. 유효한 토큰으로 허용 밖 경로를 부르면 403
 * - 세션·CSRF 를 쓰지 않는다(쿠키가 아니라 헤더로 인증)
 * - 토큰 디코더는 이 체인 안에서만 쓴다(Bean 으로 내놓지 않아 다른 모듈에 영향이 없다)
 */
@Configuration
@EnableConfigurationProperties({ReachCiProperties.class, ReachL1CollectorProperties.class})
class ReachTokenSecurityConfig {

    static final String CI = "REACH_CI";
    static final String L1 = "REACH_L1";

    /** V34 reach_scans.requested_by_repository·requested_by_subject 칸 길이 */
    private static final int REPOSITORY_MAX = 200;
    private static final int SUBJECT_MAX = 300;
    /** V42 reach_workload_observations.reported_by 칸 길이 */
    private static final int REPORTED_BY_MAX = 255;

    @Bean
    @Order(2)
    SecurityFilterChain reachTokenSecurityFilterChain(HttpSecurity http, ReachCiProperties ci,
                                                      ReachL1CollectorProperties collector) throws Exception {
        RequestMatcher reach = PathPatternRequestMatcher.withDefaults().matcher("/api/v1/reach/**");
        RequestMatcher bearer = request -> {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            return header != null && header.regionMatches(true, 0, "Bearer ", 0, 7);
        };

        http.securityMatcher(new AndRequestMatcher(reach, bearer))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/reach/ci/**").hasAuthority(CI)
                        .requestMatchers(HttpMethod.PUT, "/api/v1/reach/l1/workloads").hasAuthority(L1)
                        .anyRequest().denyAll())
                .oauth2ResourceServer(server -> server
                        .authenticationManagerResolver(managers(ci, collector))
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

    /** 발급자별 검증기. 목록에 없는 발급자는 서명을 보기 전에 401 */
    static JwtIssuerAuthenticationManagerResolver managers(ReachCiProperties ci, ReachL1CollectorProperties collector) {
        Map<String, AuthenticationManager> byIssuer = new HashMap<>();
        byIssuer.put(ci.oidc().issuer(), manager(githubDecoder(ci.oidc()), jwt -> List.of(new SimpleGrantedAuthority(CI))));
        if (collector.open()) {
            // aud 는 어떤 파드든 받을 수 있어 sub 가 수집기 서비스 계정일 때만 권한을 준다(아니면 403)
            byIssuer.put(collector.issuer(), manager(collectorDecoder(collector),
                    jwt -> collector.subject().equals(jwt.getSubject())
                            ? List.of(new SimpleGrantedAuthority(L1)) : List.of()));
        }
        return new JwtIssuerAuthenticationManagerResolver(byIssuer::get);
    }

    private static AuthenticationManager manager(JwtDecoder decoder,
                                                 Converter<Jwt, Collection<GrantedAuthority>> authorities) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(converter);
        return provider::authenticate;
    }

    /** GitHub: 서명은 발급자의 공개 키(JWKS, 첫 토큰 때 받아 캐시), 그다음 발급자·만료·aud·필요한 클레임 (②) */
    static JwtDecoder githubDecoder(ReachCiProperties.Oidc oidc) {
        return decoder(oidc.jwkSetUri(), oidc.issuer(), oidc.audience(), ReachTokenSecurityConfig::githubClaims);
    }

    /** 클러스터 서비스 계정: 서명(클러스터 발급자 JWKS)·발급자·만료·aud, sub 가 있어야 한다 */
    static JwtDecoder collectorDecoder(ReachL1CollectorProperties collector) {
        return decoder(collector.jwkSetUri(), collector.issuer(), collector.audience(),
                ReachTokenSecurityConfig::collectorClaims);
    }

    private static JwtDecoder decoder(String jwkSetUri, String issuer, String audience,
                                      OAuth2TokenValidator<Jwt> claims) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<Object>(JwtClaimNames.AUD, aud -> audienceContains(aud, audience)),
                claims));
        return decoder;
    }

    private static boolean audienceContains(Object aud, String expected) {
        if (aud instanceof Collection<?> values) return values.contains(expected);
        return expected.equals(aud);
    }

    /** 권한 판단(ReachCiAccess)과 스캔 기록(V34)에 쓰는 클레임 */
    private static OAuth2TokenValidatorResult githubClaims(Jwt jwt) {
        String repository = jwt.getClaimAsString("repository");
        String subject = jwt.getSubject();
        boolean ok = repository != null && repository.indexOf('/') > 0 && repository.length() <= REPOSITORY_MAX
                && notBlank(subject) && subject.length() <= SUBJECT_MAX
                && notBlank(jwt.getClaimAsString("event_name")) && notBlank(jwt.getClaimAsString("ref"));
        return ok ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Missing GitHub OIDC claims", null));
    }

    /** 업로드 기록(V42 reported_by)에 쓰는 클레임 */
    private static OAuth2TokenValidatorResult collectorClaims(Jwt jwt) {
        String subject = jwt.getSubject();
        boolean ok = notBlank(subject) && subject.length() <= REPORTED_BY_MAX;
        return ok ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Missing service account subject", null));
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
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
