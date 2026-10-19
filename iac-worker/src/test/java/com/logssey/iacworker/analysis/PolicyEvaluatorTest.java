package com.logssey.iacworker.analysis;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyEvaluatorTest {

    private static final Policy S3_FULL = policy(new PolicyStatement("Allow", List.of("s3:*"), List.of(), List.of("*"), List.of(), null));
    private static final Policy DENY_TFSTATE = policy(new PolicyStatement("Deny", List.of("s3:*"), List.of(),
            List.of("arn:aws:s3:::logssey-prod-s3-tfstate", "arn:aws:s3:::logssey-prod-s3-tfstate/*"), List.of(), null));

    @Test
    void explicitDenyWinsOverAllow() {
        assertThat(PolicyEvaluator.allows(List.of(S3_FULL, DENY_TFSTATE), "s3:GetObject",
                "arn:aws:s3:::logssey-prod-s3-tfstate/*")).isFalse();
        assertThat(PolicyEvaluator.allows(List.of(S3_FULL), "s3:GetObject",
                "arn:aws:s3:::logssey-prod-s3-tfstate/*")).isTrue();
        assertThat(PolicyEvaluator.allows(List.of(S3_FULL, DENY_TFSTATE), "s3:GetObject",
                "arn:aws:s3:::logssey-prod-s3-images/*")).isTrue();
    }

    @Test
    void nothingAllowedMeansDenied() {
        assertThat(PolicyEvaluator.allows(List.of(), "s3:GetObject", "arn:aws:s3:::x/*")).isFalse();
        assertThat(PolicyEvaluator.allows(List.of(DENY_TFSTATE), "s3:GetObject", "arn:aws:s3:::x/*")).isFalse();
    }

    @Test
    void wildcardsNotActionAndNotResource() {
        var secrets = policy(new PolicyStatement("Allow", List.of("secretsmanager:Get*"), List.of(),
                List.of("arn:aws:secretsmanager:ap-northeast-1:1:secret:reused/*"), List.of(), null));
        assertThat(PolicyEvaluator.allows(List.of(secrets), "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:ap-northeast-1:1:secret:reused/prod/api-ONfjwj")).isTrue();
        assertThat(PolicyEvaluator.allows(List.of(secrets), "SecretsManager:getsecretvalue",
                "arn:aws:secretsmanager:ap-northeast-1:1:secret:reused/prod/api-ONfjwj")).as("동작 이름은 대소문자 무관").isTrue();
        assertThat(PolicyEvaluator.allows(List.of(secrets), "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:ap-northeast-1:1:secret:logssey/prod/grafana")).isFalse();

        var allButIam = policy(new PolicyStatement("Allow", List.of(), List.of("iam:*"), List.of(), List.of("arn:aws:s3:::private/*"), null));
        assertThat(PolicyEvaluator.allows(List.of(allButIam), "s3:GetObject", "arn:aws:s3:::public/*")).isTrue();
        assertThat(PolicyEvaluator.allows(List.of(allButIam), "s3:GetObject", "arn:aws:s3:::private/*")).isFalse();
        assertThat(PolicyEvaluator.allows(List.of(allButIam), "iam:PassRole", "*")).isFalse();
    }

    @Test
    void conditionalDenyCountsAsDeny() {
        var conditionalDeny = policy(new PolicyStatement("Deny", List.of("s3:*"), List.of(), List.of("*"), List.of(),
                "{\"Bool\":{\"aws:SecureTransport\":\"false\"}}"));
        assertThat(PolicyEvaluator.allows(List.of(S3_FULL, conditionalDeny), "s3:GetObject", "arn:aws:s3:::x/*")).isFalse();
    }

    private static Policy policy(PolicyStatement statement) {
        return new Policy("test", "test", List.of(statement));
    }
}
