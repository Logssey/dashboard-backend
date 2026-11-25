package com.logssey.report;

import java.time.Duration;
import java.util.List;

import com.logssey.secret.aws.SecretAwsSourceCredentials;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/**
 * 운영 대시보드 API가 자기 역할 세션으로 Secrets Manager 의 Claude 키를 읽는다.
 * 시크릿 파트의 키 읽기(feat/secret 의 ClaudeApiKeySource)와 같은 비밀·설정·동작이다. 그쪽이 develop 에 들어오면 하나로 합친다.
 */
final class ReportClaudeKeySource {

    private ReportClaudeKeySource() {
    }

    static String read(String secretId, String region, String mode, String profile, String file) {
        if (secretId == null || !secretId.matches("[A-Za-z0-9/_+=.@:-]{1,512}")
                || region == null || !region.matches("[a-z]{2}(?:-[a-z]+)+-[0-9]+")) {
            throw unavailable();
        }
        protectLogging();
        try (var credentials = SecretAwsSourceCredentials.fromConfiguration(mode, profile, file);
             var client = SecretsManagerClient.builder().credentialsProvider(credentials).region(Region.of(region))
                     .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(15))
                             .apiCallAttemptTimeout(Duration.ofSeconds(8)))
                     .build()) {
            String value = client.getSecretValue(r -> r.secretId(secretId).versionStage("AWSCURRENT")).secretString();
            if (value == null || value.isBlank() || value.length() > 4_096) throw unavailable();
            value = value.strip();
            if (value.chars().anyMatch(c -> c < 0x21 || c > 0x7e)) throw unavailable();
            return value;
        } catch (RuntimeException failure) {
            throw unavailable();
        }
    }

    /** 요청·응답 본문을 남기는 로그가 켜져 있으면 키를 읽지 않는다 */
    private static void protectLogging() {
        for (String logger : List.of("software.amazon.awssdk.request", "software.amazon.awssdk.response",
                "org.apache.hc.client5.http.wire", "org.apache.http.wire")) {
            if (org.slf4j.LoggerFactory.getLogger(logger).isDebugEnabled()) throw unavailable();
        }
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("CLAUDE_KEY_STORE_UNAVAILABLE");
    }
}
