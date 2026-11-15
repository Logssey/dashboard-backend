package com.logssey.auth.github;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * GitHub 로그인 경로만 맡는 보안 설정 (ADR-D010). 기존 SecurityConfig 는 그대로 둔다.
 *
 * - 이 체인이 먼저(@Order(1)) GitHub 경로와 /api/v1/auth/options 만 받고, 나머지는 기존 체인이 받는다
 * - GitHub 등록 설정(spring.security.oauth2.client.registration.github.*)이 없으면 GitHub 경로를 열지 않는다
 *   (로컬·테스트는 지금처럼 비밀번호 로그인만)
 * - 로그인 결과는 기존 체인과 같은 세션 저장소에 남겨, 이후 API 요청이 로그인 상태가 된다
 */
@Configuration
class GitHubLoginSecurityConfig {

    static final String REGISTRATION_ID = "github";
    static final String OPTIONS_PATH = "/api/v1/auth/options";

    private static final Logger log = LoggerFactory.getLogger(GitHubLoginSecurityConfig.class);
    private static final String SUCCESS_URL = "/";
    private static final String FAILURE_URL = "/login?error=github";

    @Bean
    @Order(1)
    SecurityFilterChain gitHubLoginSecurityFilterChain(HttpSecurity http,
                                                      ObjectProvider<ClientRegistrationRepository> registrations,
                                                      SecurityContextRepository securityContextRepository,
                                                      GitHubLoginUserService userService) throws Exception {
        boolean gitHubEnabled = isGitHubEnabled(registrations.getIfAvailable());

        if (gitHubEnabled) {
            http.securityMatcher("/oauth2/**", "/login/oauth2/**", OPTIONS_PATH)
                    .oauth2Login(login -> login
                            .userInfoEndpoint(userInfo -> userInfo.userService(userService))
                            .successHandler(successHandler())
                            .failureHandler(failureHandler()));
        } else {
            http.securityMatcher(OPTIONS_PATH);
        }

        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .securityContext(context -> context.securityContextRepository(securityContextRepository))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }

    static boolean isGitHubEnabled(ClientRegistrationRepository registrations) {
        return registrations != null && registrations.findByRegistrationId(REGISTRATION_ID) != null;
    }

    /** 실패 이유는 로그에만 남기고, 화면에는 한 가지 안내(/login?error=github)만 보낸다 */
    private static SimpleUrlAuthenticationFailureHandler failureHandler() {
        SimpleUrlAuthenticationFailureHandler redirect = new SimpleUrlAuthenticationFailureHandler(FAILURE_URL);
        return new SimpleUrlAuthenticationFailureHandler(FAILURE_URL) {
            @Override
            public void onAuthenticationFailure(jakarta.servlet.http.HttpServletRequest request,
                                                jakarta.servlet.http.HttpServletResponse response,
                                                org.springframework.security.core.AuthenticationException exception)
                    throws java.io.IOException, jakarta.servlet.ServletException {
                String code = exception instanceof OAuth2AuthenticationException oauth
                        ? oauth.getError().getErrorCode() : exception.getClass().getSimpleName();
                log.info("GitHub sign-in failed. code={} reason={}", code, exception.getMessage());
                redirect.onAuthenticationFailure(request, response, exception);
            }
        };
    }

    private static SimpleUrlAuthenticationSuccessHandler successHandler() {
        SimpleUrlAuthenticationSuccessHandler handler = new SimpleUrlAuthenticationSuccessHandler(SUCCESS_URL);
        // 로그인 전에 보던 주소로 돌아가지 않고 항상 첫 화면으로 간다
        handler.setAlwaysUseDefaultTargetUrl(true);
        return handler;
    }
}
