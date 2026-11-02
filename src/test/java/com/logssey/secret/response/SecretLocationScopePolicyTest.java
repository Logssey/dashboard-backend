package com.logssey.secret.response;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class SecretLocationScopePolicyTest {
    @Test
    void acceptsOnlyExactCurrentAwsContentAndPreservesGithubSupport() {
        assertThat(SecretLocationScopePolicy.approved("GITHUB", "GITHUB_REPOSITORY_FILES",
                "CURRENT_COMMIT_ONLY", "github://Logssey/example/main/src/")).isTrue();
        assertThat(SecretLocationScopePolicy.approved("AWS", "AWS_SECRETS_MANAGER_VALUE",
                "CURRENT_VALUE_ONLY", "aws://123456789012/ap-northeast-2/secrets-manager/secret/arn%3Aaws%3Asecretsmanager%3Aap-northeast-2%3A123456789012%3Asecret%3Atest")).isTrue();
        assertThat(SecretLocationScopePolicy.approved("AWS", "AWS_SSM_PARAMETER_VALUE",
                "CURRENT_VALUE_ONLY", "aws://123456789012/ap-northeast-2/ssm/parameter/arn%3Aaws%3Assm%3Aap-northeast-2%3A123456789012%3Aparameter%2Ftest")).isTrue();
        assertThat(SecretLocationScopePolicy.approved("AWS", "AWS_S3_OBJECT_CONTENT",
                "CURRENT_VALUE_ONLY", "aws://123456789012/ap-northeast-2/s3/object/example-bucket/config%2Fapp.env")).isTrue();
    }

    @Test
    void rejectsMetadataProviderMismatchBroadPathsAndNonCurrentHistory() {
        assertThat(SecretLocationScopePolicy.approved("AWS", "IAM_ACCESS_KEY_METADATA",
                "CURRENT_STATE_ONLY", "aws://123456789012/global/iam/access-keys")).isFalse();
        assertThat(SecretLocationScopePolicy.approved("AWS", "GITHUB_REPOSITORY_FILES",
                "CURRENT_COMMIT_ONLY", "github://Logssey/example/main/src/")).isFalse();
        assertThat(SecretLocationScopePolicy.approved("GITHUB", "AWS_S3_OBJECT_CONTENT",
                "CURRENT_VALUE_ONLY", "aws://123456789012/ap-northeast-2/s3/object/example-bucket/app.env")).isFalse();
        for (String ref : new String[]{null, "aws://123456789012/ap-northeast-2/s3/object/example-bucket/*",
                "aws://123456789012/ap-northeast-2/s3/object/example-bucket/dir/file.env",
                "aws://123456789012/ap-northeast-2/s3/object/example-bucket/file.env?version=other"}) {
            assertThat(SecretLocationScopePolicy.approved("AWS", "AWS_S3_OBJECT_CONTENT",
                    "CURRENT_VALUE_ONLY", ref)).isFalse();
        }
        assertThat(SecretLocationScopePolicy.approved("AWS", "AWS_S3_OBJECT_CONTENT",
                "CURRENT_STATE_ONLY", "aws://123456789012/ap-northeast-2/s3/object/example-bucket/app.env")).isFalse();
    }
}
