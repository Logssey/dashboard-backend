package com.logssey.reach.l1;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * L1 수집기 토큰 (클러스터 서비스 계정 토큰). 수집기는 PUT /api/v1/reach/l1/workloads 를 이 토큰으로 부른다.
 * issuer 가 비어 있으면 수집기 토큰을 받지 않는다(설치 설정을 넣기 전에는 닫혀 있다).
 * audience 는 클러스터의 어떤 파드든 요청해 받을 수 있으므로 subject(수집기 서비스 계정)까지 맞아야 업로드할 수 있다
 */
@ConfigurationProperties("logssey.reach.l1.collector")
public record ReachL1CollectorProperties(String issuer, String jwkSetUri,
                                         @DefaultValue(AUDIENCE) String audience,
                                         @DefaultValue(SUBJECT) String subject) {

    static final String AUDIENCE = "logssey-reach-l1";
    static final String SUBJECT = "system:serviceaccount:reach:reach-l1-collector";
    /** 쿠버네티스 API 서버가 공개하는 서명 키 경로 (서비스 계정 발급자 검색 문서의 jwks_uri) */
    static final String JWKS_PATH = "/openid/v1/jwks";

    public ReachL1CollectorProperties {
        issuer = issuer == null || issuer.isBlank() ? null : issuer;
        jwkSetUri = jwkSetUri == null || jwkSetUri.isBlank() ? (issuer == null ? null : issuer + JWKS_PATH) : jwkSetUri;
        audience = audience == null || audience.isBlank() ? AUDIENCE : audience;
        subject = subject == null || subject.isBlank() ? SUBJECT : subject;
    }

    /** 설정이 없을 때(수집기 토큰을 받지 않음) */
    public static ReachL1CollectorProperties closed() {
        return new ReachL1CollectorProperties(null, null, null, null);
    }

    public boolean open() {
        return issuer != null;
    }
}
