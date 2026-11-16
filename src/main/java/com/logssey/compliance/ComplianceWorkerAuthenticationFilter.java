package com.logssey.compliance;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Worker shared token boundary. Production may replace this with workload identity or mTLS. */
@Component
public class ComplianceWorkerAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Compliance-Worker-Token";
    private static final String PATH_PREFIX = "/internal/v1/compliance/";

    private final byte[] expectedToken;

    public ComplianceWorkerAuthenticationFilter(
            @Value("${logssey.compliance.worker-token:}") String workerToken) {
        this.expectedToken = workerToken.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(PATH_PREFIX);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String supplied = request.getHeader(HEADER);
        boolean configured = expectedToken.length >= 24;
        boolean matches = supplied != null && MessageDigest.isEqual(
                expectedToken, supplied.getBytes(StandardCharsets.UTF_8));
        if (!configured || !matches) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write("{\"code\":\"COMPLIANCE_WORKER_UNAUTHENTICATED\","
                    + "\"message\":\"컴플라이언스 Worker 인증에 실패했습니다.\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
