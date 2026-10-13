package com.logssey.secretworker.aws.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

class AwsMetadataApprovedScopeTest {
    private static final String ACCOUNT = "123456789012";

    @Test
    void parsesOneApprovedRegionAtATimeAcrossSeventeenFixtureRegions() {
        List<String> regions = List.of("us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
                "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2",
                "ap-southeast-3", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
                "sa-east-1");
        assertThat(regions).hasSize(17);
        for (String region : regions) {
            var secrets = AwsMetadataApprovedScope.parse("AWS_SECRETS_MANAGER_METADATA",
                    "aws://" + ACCOUNT + "/" + region + "/secrets-manager/all", "CURRENT_STATE_ONLY");
            var parameters = AwsMetadataApprovedScope.parse("AWS_SSM_PARAMETER_METADATA",
                    "aws://" + ACCOUNT + "/" + region + "/ssm/parameters", "CURRENT_STATE_ONLY");
            assertThat(secrets.region()).isEqualTo(region);
            assertThat(parameters.region()).isEqualTo(region);
            assertThat(secrets.service()).isEqualTo(AwsMetadataCollector.Service.SECRETS_MANAGER);
            assertThat(parameters.service()).isEqualTo(AwsMetadataCollector.Service.SSM_PARAMETER);
        }
        var buckets = AwsMetadataApprovedScope.parse("AWS_S3_BUCKET_METADATA",
                "aws://" + ACCOUNT + "/global/s3/buckets", "CURRENT_STATE_ONLY");
        assertThat(buckets.region()).isEqualTo("global");
        assertThat(buckets.toString()).doesNotContain(ACCOUNT);
    }

    @Test
    void refusesValuePathsQueriesAndUnapprovedHistoryWithoutNetworkCall() {
        for (String ref : List.of(
                "aws://" + ACCOUNT + "/ap-northeast-2/secrets-manager/value",
                "aws://" + ACCOUNT + "/ap-northeast-2/secrets-manager/all?value=true",
                "aws://" + ACCOUNT + "/global/secrets-manager/all",
                "aws://" + ACCOUNT + "/ap-northeast-2/ssm/parameters/secret")) {
            assertThatThrownBy(() -> AwsMetadataApprovedScope.parse(
                    "AWS_SECRETS_MANAGER_METADATA", ref, "CURRENT_STATE_ONLY"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> AwsMetadataApprovedScope.parse("AWS_S3_BUCKET_METADATA",
                "aws://" + ACCOUNT + "/global/s3/buckets", "ALL_HISTORY"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
