package com.logssey.secretworker.aws.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayDeque;
import java.util.Deque;

import org.junit.jupiter.api.Test;

class AwsMetadataCollectorTest {
    @Test
    void paginatesEachApprovedServiceWithoutReturningIdentifiersOrTokens() {
        FakePages pages = new FakePages();
        pages.secrets.add(new AwsMetadataPageClient.Page(2, "sensitive-next-token"));
        pages.secrets.add(new AwsMetadataPageClient.Page(3, null));
        pages.parameters.add(new AwsMetadataPageClient.Page(4, null));
        pages.buckets.add(new AwsMetadataPageClient.Page(1, null));

        AwsMetadataCollector collector = new AwsMetadataCollector(pages);
        var secrets = collector.collect(AwsMetadataCollector.Service.SECRETS_MANAGER, "ap-northeast-2");
        var parameters = collector.collect(AwsMetadataCollector.Service.SSM_PARAMETER, "ap-northeast-2");
        var buckets = collector.collect(AwsMetadataCollector.Service.S3_BUCKET, "global");

        assertEquals(AwsMetadataCollector.Status.SUCCEEDED, secrets.status());
        assertEquals(5, secrets.objectCount());
        assertEquals(2, secrets.pagesRead());
        assertEquals(4, parameters.objectCount());
        assertEquals(1, buckets.objectCount());
        assertEquals("sensitive-next-token", pages.lastSecretsToken);
        assertFalse(secrets.toString().contains("sensitive-next-token"));
        assertFalse(new AwsMetadataPageClient.Page(1, "sensitive-next-token").toString()
                .contains("sensitive-next-token"));
    }

    @Test
    void recordsPartialAndFailedCoverageWithFixedCodesOnly() {
        FakePages pages = new FakePages();
        pages.secrets.add(new AwsMetadataPageClient.Page(2, "next"));
        pages.secrets.add(new AwsMetadataPageClient.Failure(AwsMetadataCollector.GapCode.ACCESS_DENIED));
        pages.parameters.add(new AwsMetadataPageClient.Failure(AwsMetadataCollector.GapCode.RATE_LIMITED));

        AwsMetadataCollector collector = new AwsMetadataCollector(pages);
        var partial = collector.collect(AwsMetadataCollector.Service.SECRETS_MANAGER, "us-east-1");
        var failed = collector.collect(AwsMetadataCollector.Service.SSM_PARAMETER, "us-east-1");

        assertEquals(AwsMetadataCollector.Status.PARTIAL, partial.status());
        assertEquals(2, partial.objectCount());
        assertEquals(AwsMetadataCollector.GapCode.ACCESS_DENIED, partial.gaps().getFirst());
        assertEquals(AwsMetadataCollector.Status.FAILED, failed.status());
        assertEquals(0, failed.objectCount());
        assertEquals(AwsMetadataCollector.GapCode.RATE_LIMITED, failed.gaps().getFirst());
    }

    @Test
    void boundedPaginationAndScopeValidationAvoidUnapprovedCalls() {
        FakePages pages = new FakePages();
        pages.secrets.add(new AwsMetadataPageClient.Page(1, "loop"));
        pages.secrets.add(new AwsMetadataPageClient.Page(1, "loop"));
        AwsMetadataCollector collector = new AwsMetadataCollector(pages);
        var result = collector.collect(AwsMetadataCollector.Service.SECRETS_MANAGER, "eu-west-1");
        assertEquals(AwsMetadataCollector.Status.PARTIAL, result.status());
        assertEquals(AwsMetadataCollector.GapCode.PAGINATION_LOOP, result.gaps().getFirst());

        assertThrows(IllegalArgumentException.class,
                () -> collector.collect(AwsMetadataCollector.Service.SSM_PARAMETER, "global"));
        assertThrows(IllegalArgumentException.class,
                () -> collector.collect(AwsMetadataCollector.Service.S3_BUCKET, "eu-west-1"));
        assertThrows(IllegalArgumentException.class,
                () -> collector.collect(AwsMetadataCollector.Service.SECRETS_MANAGER, "us-east-1/other"));
        assertEquals(0, pages.parameterCalls);
        assertEquals(0, pages.bucketCalls);
    }

    @Test
    void reportsPageAndObjectLimitsAsCoverageGaps() {
        FakePages pages = new FakePages();
        pages.secrets.add(new AwsMetadataPageClient.Page(1, "next"));
        var pageLimit = new AwsMetadataCollector(pages, new AwsMetadataCollector.Limits(1, 10))
                .collect(AwsMetadataCollector.Service.SECRETS_MANAGER, "us-west-2");
        assertEquals(AwsMetadataCollector.Status.PARTIAL, pageLimit.status());
        assertEquals(AwsMetadataCollector.GapCode.PAGE_LIMIT, pageLimit.gaps().getFirst());

        pages.parameters.add(new AwsMetadataPageClient.Page(3, null));
        var objectLimit = new AwsMetadataCollector(pages, new AwsMetadataCollector.Limits(2, 2))
                .collect(AwsMetadataCollector.Service.SSM_PARAMETER, "us-west-2");
        assertEquals(AwsMetadataCollector.Status.FAILED, objectLimit.status());
        assertEquals(AwsMetadataCollector.GapCode.OBJECT_LIMIT, objectLimit.gaps().getFirst());
        assertTrue(objectLimit.gaps().toString().contains("OBJECT_LIMIT"));
    }

    private static final class FakePages implements AwsMetadataPageClient {
        final Deque<Object> secrets = new ArrayDeque<>();
        final Deque<Object> parameters = new ArrayDeque<>();
        final Deque<Object> buckets = new ArrayDeque<>();
        String lastSecretsToken;
        int parameterCalls;
        int bucketCalls;

        @Override public Page listSecrets(String region, String nextToken) {
            lastSecretsToken = nextToken;
            return pop(secrets);
        }

        @Override public Page describeParameters(String region, String nextToken) {
            parameterCalls++;
            return pop(parameters);
        }

        @Override public Page listBuckets(String nextToken) {
            bucketCalls++;
            return pop(buckets);
        }

        private Page pop(Deque<Object> queue) {
            Object value = queue.removeFirst();
            if (value instanceof Failure failure) throw failure;
            return (Page) value;
        }
    }
}
