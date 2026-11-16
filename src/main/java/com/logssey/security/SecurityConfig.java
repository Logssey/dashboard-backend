package com.logssey.security;

import com.logssey.compliance.ComplianceWorkerAuthenticationFilter;
import com.logssey.runtime.security.RuntimeCollectorAuthenticationFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 로그인 방식 (ADR-D003)
 * - 서버 세션으로 로그인 유지 (JWT 사용 안 함)
 * - CSRF: 서버가 XSRF-TOKEN 쿠키를 주고, 화면은 POST 요청에 X-XSRF-TOKEN 헤더로 돌려보낸다
 * - 로그인·로그아웃만 로그인 없이 호출 가능, 나머지 API는 로그인 필요
 */
@Configuration
public class SecurityConfig {

    private final RuntimeCollectorAuthenticationFilter runtimeCollectorAuthenticationFilter;
    private final ComplianceWorkerAuthenticationFilter complianceWorkerAuthenticationFilter;

    public SecurityConfig(RuntimeCollectorAuthenticationFilter runtimeCollectorAuthenticationFilter,
                          ComplianceWorkerAuthenticationFilter complianceWorkerAuthenticationFilter) {
        this.runtimeCollectorAuthenticationFilter = runtimeCollectorAuthenticationFilter;
        this.complianceWorkerAuthenticationFilter = complianceWorkerAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers("/internal/v1/runtime/**", "/internal/v1/compliance/**"))
                .addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class)
                .addFilterBefore(runtimeCollectorAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(complianceWorkerAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/logout").permitAll()
                        .requestMatchers("/internal/v1/runtime/**").permitAll()
                        .requestMatchers("/internal/v1/compliance/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(JsonSecurityErrorHandlers.unauthenticated())
                        .accessDeniedHandler(JsonSecurityErrorHandlers.forbidden()))
                .securityContext(context -> context.securityContextRepository(securityContextRepository()))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** 아이디가 없을 때와 비밀번호가 틀릴 때 모두 같은 예외(BadCredentialsException)를 낸다 */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }
}
