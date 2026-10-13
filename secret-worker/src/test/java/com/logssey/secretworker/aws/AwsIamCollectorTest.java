package com.logssey.secretworker.aws;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AwsIamCollectorTest {
    private static final AwsApprovedScope SCOPE = AwsApprovedScope.parse(
            "IAM_ACCESS_KEY_METADATA", "aws://123456789012/global/iam/access-keys",
            "CURRENT_STATE_ONLY");

    @Test
    void scopeRequiresExactAccountGlobalIamPathAndMetadataType() {
        assertThat(SCOPE.accountId()).isEqualTo("123456789012");
        for (String ref : List.of("aws://123456789012/ap-northeast-1/iam/access-keys",
                "aws://123456789012/global/iam/access-keys/other",
                "aws://123456789012/global/iam/access-keys?all=true")) {
            assertThatThrownBy(() -> AwsApprovedScope.parse(
                    "IAM_ACCESS_KEY_METADATA", ref, "CURRENT_STATE_ONLY"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> AwsApprovedScope.parse("AWS_SECRET_VALUE",
                "aws://123456789012/global/iam/access-keys", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void mismatchedAccountDoesNotListUsersOrKeys() {
        var gateway = new FakeGateway();
        gateway.account = "000000000000";
        var result = new AwsIamCollector(gateway).collect(SCOPE, (key, use) -> { });
        assertThat(result.status()).isEqualTo(AwsIamCollector.Status.FAILED);
        assertThat(result.gaps()).containsExactly(AwsIamCollector.GapCode.ACCOUNT_MISMATCH);
        assertThat(gateway.actions).containsExactly("GetCallerIdentity");
    }

    @Test
    void pagesThroughUsersAndKeysAndReturnsOnlyCountsAndSafeGaps() {
        var gateway = new FakeGateway();
        var seen = new ArrayList<String>();
        var result = new AwsIamCollector(gateway).collect(SCOPE,
                (key, usage) -> seen.add(key.id()));
        assertThat(result.status()).isEqualTo(AwsIamCollector.Status.SUCCEEDED);
        assertThat(result.objectCount()).isEqualTo(2);
        assertThat(seen).containsExactly("AKIAABCDEFGHIJKLMNOP", "AKIAQRSTUVWXYZABCDEF");
        assertThat(gateway.actions).containsExactly("GetCallerIdentity", "GetAccountSummary", "ListUsers:first",
                "ListAccessKeys:alice:first", "GetAccessKeyLastUsed",
                "ListAccessKeys:alice:next", "GetAccessKeyLastUsed", "ListUsers:next");
        assertThat(result.toString()).doesNotContain("AKIA", "alice");
    }

    @Test
    void keyUsageFailureIsPartialButKeepsKeyMetadata() {
        var gateway = new FakeGateway();
        gateway.failLastUsed = true;
        var seen = new ArrayList<AwsIamGateway.LastUsed>();
        var result = new AwsIamCollector(gateway).collect(SCOPE,
                (key, usage) -> seen.add(usage));
        assertThat(result.status()).isEqualTo(AwsIamCollector.Status.PARTIAL);
        assertThat(result.objectCount()).isEqualTo(2);
        assertThat(result.gaps()).contains(AwsIamCollector.GapCode.LAST_USED_UNAVAILABLE);
        assertThat(seen).allMatch(usage -> usage.at() == null);
    }

    @Test
    void rootKeyPresenceMakesUserListingPartialWithoutFetchingRootKeyValue() {
        var gateway = new FakeGateway();
        gateway.rootKeys = 1;
        var result = new AwsIamCollector(gateway).collect(SCOPE, (key, usage) -> { });
        assertThat(result.status()).isEqualTo(AwsIamCollector.Status.PARTIAL);
        assertThat(result.gaps()).containsExactly(AwsIamCollector.GapCode.ROOT_ACCESS_KEYS_PRESENT);
        assertThat(gateway.actions).doesNotContain("GetRootAccessKey");
    }

    @Test
    void collectionRecordsNoRawIdentifiersInDiagnosticRecords() {
        var key = new AwsIamGateway.AccessKey("AKIAABCDEFGHIJKLMNOP", "alice",
                "Active", Instant.EPOCH);
        var page = new AwsIamGateway.Page<>(List.of(key), "secret-marker");
        assertThat(key.toString()).doesNotContain("AKIA", "alice");
        assertThat(page.toString()).doesNotContain("AKIA", "alice", "secret-marker");
    }

    private static final class FakeGateway implements AwsIamGateway {
        String account = "123456789012";
        boolean failLastUsed;
        int rootKeys;
        final List<String> actions = new ArrayList<>();

        @Override public String accountId() {
            actions.add("GetCallerIdentity");
            return account;
        }

        @Override public Page<String> users(String marker) {
            actions.add("ListUsers:" + (marker == null ? "first" : marker));
            return marker == null ? new Page<>(List.of("alice"), "next")
                    : new Page<>(List.of(), null);
        }

        @Override public Page<AccessKey> accessKeys(String userName, String marker) {
            actions.add("ListAccessKeys:" + userName + ":" + (marker == null ? "first" : marker));
            return marker == null ? new Page<>(List.of(new AccessKey(
                    "AKIAABCDEFGHIJKLMNOP", userName, "Active", Instant.EPOCH)), "next")
                    : new Page<>(List.of(new AccessKey(
                    "AKIAQRSTUVWXYZABCDEF", userName, "Inactive", Instant.EPOCH)), null);
        }

        @Override public LastUsed lastUsed(String accessKeyId) {
            actions.add("GetAccessKeyLastUsed");
            if (failLastUsed) {
                throw new AwsIamSourceException(AwsIamSourceException.Code.ACCESS_DENIED);
            }
            return new LastUsed(Instant.EPOCH, "Amazon S3", "ap-northeast-1");
        }

        @Override public int rootAccessKeyCount() {
            actions.add("GetAccountSummary");
            return rootKeys;
        }
    }
}
