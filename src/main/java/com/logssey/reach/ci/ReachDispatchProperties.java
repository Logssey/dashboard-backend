package com.logssey.reach.ci;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 대시보드에서 요청한 스캔(API-01)을 서비스 레포의 Reach 워크플로로 띄우는 GitHub App (ARD AD-18 ③).
 * appId·privateKey가 비면 띄우지 않는다(스캔은 QUEUED로 남는다). 레포 소유자와 브랜치는 logssey.reach.ci 설정을 쓴다.
 * privateKey는 GitHub이 준 PEM 그대로(PKCS#1 "RSA PRIVATE KEY" 또는 PKCS#8 "PRIVATE KEY"). 운영은 /run/secrets 파일
 */
@ConfigurationProperties("logssey.reach.dispatch")
public record ReachDispatchProperties(String appId, String privateKey,
                                      @DefaultValue("reach.yml") String workflow,
                                      @DefaultValue("https://api.github.com") String apiBaseUrl) {

    public ReachDispatchProperties {
        workflow = workflow == null || workflow.isBlank() ? "reach.yml" : workflow;
        apiBaseUrl = apiBaseUrl == null || apiBaseUrl.isBlank() ? "https://api.github.com" : apiBaseUrl;
    }

    /** 설정이 없을 때(띄우지 않는다) */
    public static ReachDispatchProperties closed() {
        return new ReachDispatchProperties(null, null, null, null);
    }

    public boolean open() {
        return appId != null && !appId.isBlank() && privateKey != null && !privateKey.isBlank();
    }
}
