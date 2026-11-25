package com.logssey.iac.auth;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import com.logssey.common.error.ApiErrorResponse;
import com.logssey.common.error.ErrorCode;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
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
 * infrastructure 의 iac-report(PR)·iac-drift(main 매일 점검) 워크플로가 실행을 등록하고 plan 을 올릴 때의 인증
 * (GitHub Actions OIDC, IaC 보안 ADR-13).
 * 기존 SecurityConfig·Reach 체인은 그대로 둔다 (같은 방식의 별도 체인).
 *
 * - Bearer 헤더가 있는 /api/v1/iac/runs/** 만 받는다. 헤더가 없으면 기존 체인(대시보드 관리자 세션)이 받는다
 * - 서명(GitHub JWKS)·발급자·만료·aud(logssey-iac)·sub(IacCiProperties 의 둘 중 하나와 정확히 같음)·repository 클레임을
 *   본다. 틀리면 401. sub 마다 다룰 수 있는 실행 종류(PR·PUSH)가 정해져 있다 (IacCiCaller)
 * - 허용: 실행 등록, plan 업로드, 실행 상태·결과. 그 밖은 403. 레포 확인은 IacRunService·IacQueryService 가 한다
 * - 토큰 디코더는 이 체인 안에서만 쓴다 (Bean 으로 내놓지 않는다)
 */
@Configuration
@EnableConfigurationProperties(IacCiProperties.class)
public class IacCiSecurityConfig {

    public static final String AUTHORITY = "IAC_CI";
    private static final String TRIGGER_PREFIX = "IAC_CI_TRIGGER_";
    private static final String RUNS = "/api/v1/iac/runs";
    /** iac_repos.full_name 길이 */
    private static final int REPOSITORY_MAX = 200;

    @Bean
    @Order(4)
    SecurityFilterChain iacCiSecurityFilterChain(HttpSecurity http, IacCiProperties properties) throws Exception {
        var paths = PathPatternRequestMatcher.withDefaults();
        RequestMatcher bearer = request -> {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            return header != null && header.regionMatches(true, 0, "Bearer ", 0, 7);
        };
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> List.of(new SimpleGrantedAuthority(AUTHORITY),
                new SimpleGrantedAuthority(TRIGGER_PREFIX + properties.triggerOf(jwt.getSubject()))));

        http.securityMatcher(new AndRequestMatcher(paths.matcher(RUNS + "/**"), bearer))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(paths.matcher(HttpMethod.POST, RUNS)).hasAuthority(AUTHORITY)
                        .requestMatchers(paths.matcher(HttpMethod.PUT, RUNS + "/{runId}/plan")).hasAuthority(AUTHORITY)
                        .requestMatchers(paths.matcher(HttpMethod.GET, RUNS + "/{runId}")).hasAuthority(AUTHORITY)
                        .requestMatchers(paths.matcher(HttpMethod.GET, RUNS + "/{runId}/result")).hasAuthority(AUTHORITY)
                        .anyRequest().denyAll())
                .oauth2ResourceServer(server -> server
                        .jwt(jwt -> jwt.decoder(decoder(properties)).jwtAuthenticationConverter(converter))
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

    /** CI 로 인증된 요청이면 토큰의 레포(예: Logssey/infrastructure)와 다룰 수 있는 실행 종류 */
    public static Optional<IacCiCaller> ciCaller(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)
                || authentication.getAuthorities().stream().noneMatch(a -> AUTHORITY.equals(a.getAuthority()))) {
            return Optional.empty();
        }
        String trigger = authentication.getAuthorities().stream().map(a -> a.getAuthority())
                .filter(a -> a.startsWith(TRIGGER_PREFIX)).map(a -> a.substring(TRIGGER_PREFIX.length()))
                .findFirst().orElseThrow();
        return Optional.of(new IacCiCaller(jwt.getClaimAsString("repository"), trigger));
    }

    static JwtDecoder decoder(IacCiProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()),
                new JwtClaimValidator<Object>(JwtClaimNames.AUD, aud -> audienceContains(aud, properties.audience())),
                jwt -> claims(jwt, properties)));
        return decoder;
    }

    private static boolean audienceContains(Object aud, String expected) {
        if (aud instanceof Collection<?> values) return values.contains(expected);
        return expected.equals(aud);
    }

    /** sub 는 정해진 워크플로 둘 중 하나와 정확히 같아야 하고, 레포 확인에 쓸 repository 가 있어야 한다 */
    private static OAuth2TokenValidatorResult claims(Jwt jwt, IacCiProperties properties) {
        String repository = jwt.getClaimAsString("repository");
        boolean ok = properties.triggerOf(jwt.getSubject()) != null
                && repository != null && repository.indexOf('/') > 0 && repository.length() <= REPOSITORY_MAX;
        return ok ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Not the IaC report workflow", null));
    }

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
