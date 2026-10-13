package com.logssey.secretworker.aws.metadata;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Counts metadata within one approved service/region scope without exporting resource identifiers. */
public final class AwsMetadataCollector {
    private static final Pattern REGION = Pattern.compile("^[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]+$");
    private static final int MAX_TOKEN_LENGTH = 4096;

    public enum Service { SECRETS_MANAGER, SSM_PARAMETER, S3_BUCKET }
    public enum Status { SUCCEEDED, PARTIAL, FAILED }
    public enum GapCode {
        ACCESS_DENIED, RATE_LIMITED, SOURCE_UNAVAILABLE, API_ERROR,
        MALFORMED_RESPONSE, PAGE_LIMIT, OBJECT_LIMIT, PAGINATION_LOOP
    }

    public record Limits(int maxPages, int maxObjects) {
        public static final Limits DEFAULT = new Limits(200, 100_000);

        public Limits {
            if (maxPages < 1 || maxObjects < 1) throw new IllegalArgumentException("Invalid AWS metadata limits");
        }
    }

    /** No name, ARN, description, account, region or continuation token is returned. */
    public record Result(Status status, int objectCount, int pagesRead, List<GapCode> gaps) {
        public Result {
            gaps = List.copyOf(gaps);
        }
    }

    private final AwsMetadataPageClient pages;
    private final Limits limits;

    public AwsMetadataCollector(AwsMetadataPageClient pages) {
        this(pages, Limits.DEFAULT);
    }

    public AwsMetadataCollector(AwsMetadataPageClient pages, Limits limits) {
        this.pages = Objects.requireNonNull(pages);
        this.limits = Objects.requireNonNull(limits);
    }

    /** Caller must first verify the account and approved scope; this method never enumerates regions. */
    public Result collect(Service service, String region) {
        Objects.requireNonNull(service);
        if (service == Service.S3_BUCKET) {
            if (!"global".equals(region)) throw new IllegalArgumentException("Invalid S3 metadata region");
        } else if (region == null || !REGION.matcher(region).matches()) {
            throw new IllegalArgumentException("Invalid AWS metadata region");
        }

        String token = null;
        Set<String> seenTokens = new HashSet<>();
        List<GapCode> gaps = new ArrayList<>();
        int count = 0;
        int pagesRead = 0;
        do {
            if (pagesRead == limits.maxPages()) {
                gaps.add(GapCode.PAGE_LIMIT);
                break;
            }
            AwsMetadataPageClient.Page page;
            try {
                page = switch (service) {
                    case SECRETS_MANAGER -> pages.listSecrets(region, token);
                    case SSM_PARAMETER -> pages.describeParameters(region, token);
                    case S3_BUCKET -> pages.listBuckets(token);
                };
            } catch (AwsMetadataPageClient.Failure failure) {
                gaps.add(failure.code());
                break;
            } catch (RuntimeException unexpected) {
                gaps.add(GapCode.API_ERROR);
                break;
            }
            if (page == null || page.itemCount() < 0 || page.itemCount() > limits.maxObjects() - count) {
                gaps.add(page == null ? GapCode.MALFORMED_RESPONSE : GapCode.OBJECT_LIMIT);
                break;
            }
            pagesRead++;
            count += page.itemCount();
            token = page.nextToken();
            if (token != null && (token.isBlank() || token.length() > MAX_TOKEN_LENGTH)) {
                gaps.add(GapCode.MALFORMED_RESPONSE);
                break;
            }
            if (token != null && !seenTokens.add(token)) {
                gaps.add(GapCode.PAGINATION_LOOP);
                break;
            }
        } while (token != null);
        Status status = gaps.isEmpty() ? Status.SUCCEEDED : pagesRead == 0 ? Status.FAILED : Status.PARTIAL;
        return new Result(status, count, pagesRead, gaps);
    }
}
