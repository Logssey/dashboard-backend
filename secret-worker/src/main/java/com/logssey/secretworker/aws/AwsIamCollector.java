package com.logssey.secretworker.aws;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** IAM access-key metadata only: no secret retrieval or credential validation. */
public final class AwsIamCollector {
    private static final int MAX_USERS = 1_000;
    private static final int MAX_KEYS = 2_000;
    private static final int MAX_PAGES = 100;

    private final AwsIamGateway gateway;

    public AwsIamCollector(AwsIamGateway gateway) {
        this.gateway = gateway;
    }

    public AwsIamCollector observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) {
        return new AwsIamCollector(gateway.observed(observer));
    }

    @FunctionalInterface
    public interface MetadataSink {
        void accept(AwsIamGateway.AccessKey key, AwsIamGateway.LastUsed lastUsed);
    }

    public enum Status { SUCCEEDED, PARTIAL, FAILED }
    public enum GapCode { ACCOUNT_MISMATCH, ACCESS_DENIED, RATE_LIMITED, UNAVAILABLE,
        INVALID_RESPONSE, USER_LIMIT, KEY_LIMIT, PAGE_LIMIT, LAST_USED_UNAVAILABLE,
        ROOT_ACCESS_KEYS_PRESENT, ROOT_KEY_COVERAGE_UNKNOWN }
    public record Result(Status status, int objectCount, List<GapCode> gaps) { }

    public Result collect(AwsApprovedScope scope, MetadataSink sink) {
        List<GapCode> gaps = new ArrayList<>();
        int count = 0;
        boolean usersListed = false;
        try {
            if (!scope.accountId().equals(gateway.accountId())) {
                return new Result(Status.FAILED, 0, List.of(GapCode.ACCOUNT_MISMATCH));
            }
            try {
                if (gateway.rootAccessKeyCount() > 0) {
                    gaps.add(GapCode.ROOT_ACCESS_KEYS_PRESENT);
                }
            } catch (AwsIamSourceException error) {
                gaps.add(GapCode.ROOT_KEY_COVERAGE_UNKNOWN);
            }
            String marker = null;
            Set<String> seenMarkers = new HashSet<>();
            int users = 0;
            int pages = 0;
            boolean stop = false;
            do {
                if (++pages > MAX_PAGES) {
                    gaps.add(GapCode.PAGE_LIMIT);
                    break;
                }
                var page = gateway.users(marker);
                if (page == null || page.items() == null) {
                    gaps.add(GapCode.INVALID_RESPONSE);
                    break;
                }
                usersListed = true;
                for (int index = 0; index < page.items().size(); index++) {
                    String user = page.items().get(index);
                    if (++users > MAX_USERS) {
                        gaps.add(GapCode.USER_LIMIT);
                        stop = true;
                        break;
                    }
                    if (user == null || user.isBlank()) {
                        gaps.add(GapCode.INVALID_RESPONSE);
                        continue;
                    }
                    count += collectUser(user, sink, gaps, MAX_KEYS - count);
                    if (count >= MAX_KEYS) {
                        if (index < page.items().size() - 1 || page.nextMarker() != null) {
                            gaps.add(GapCode.KEY_LIMIT);
                        }
                        stop = true;
                        break;
                    }
                }
                if (stop) break;
                marker = next(page.nextMarker(), seenMarkers, gaps);
            } while (marker != null);
        } catch (AwsIamSourceException error) {
            gaps.add(map(error.code()));
        }
        return new Result(gaps.isEmpty() ? Status.SUCCEEDED
                : usersListed ? Status.PARTIAL : Status.FAILED, count, List.copyOf(gaps));
    }

    private int collectUser(String user, MetadataSink sink, List<GapCode> gaps, int remaining) {
        int count = 0;
        int pages = 0;
        String marker = null;
        Set<String> seenMarkers = new HashSet<>();
        try {
            do {
                if (++pages > MAX_PAGES) {
                    gaps.add(GapCode.PAGE_LIMIT);
                    break;
                }
                var page = gateway.accessKeys(user, marker);
                if (page == null || page.items() == null) {
                    gaps.add(GapCode.INVALID_RESPONSE);
                    break;
                }
                for (var key : page.items()) {
                    if (count >= remaining) {
                        gaps.add(GapCode.KEY_LIMIT);
                        return count;
                    }
                    if (key == null || key.id() == null
                            || !key.id().matches("[A-Za-z0-9_]{16,128}")
                            || !user.equals(key.userName())) {
                        gaps.add(GapCode.INVALID_RESPONSE);
                        continue;
                    }
                    AwsIamGateway.LastUsed usage;
                    try {
                        usage = gateway.lastUsed(key.id());
                    } catch (AwsIamSourceException error) {
                        gaps.add(GapCode.LAST_USED_UNAVAILABLE);
                        usage = new AwsIamGateway.LastUsed(null, null, null);
                    }
                    sink.accept(key, usage);
                    count++;
                }
                if (count >= remaining && page.nextMarker() != null) {
                    gaps.add(GapCode.KEY_LIMIT);
                    break;
                }
                marker = next(page.nextMarker(), seenMarkers, gaps);
            } while (marker != null);
        } catch (AwsIamSourceException error) {
            gaps.add(map(error.code()));
        }
        return count;
    }

    private static String next(String marker, Set<String> seen, List<GapCode> gaps) {
        if (marker == null) return null;
        if (marker.isBlank() || !seen.add(marker)) {
            gaps.add(GapCode.INVALID_RESPONSE);
            return null;
        }
        return marker;
    }

    private static GapCode map(AwsIamSourceException.Code code) {
        return switch (code) {
            case ACCESS_DENIED -> GapCode.ACCESS_DENIED;
            case RATE_LIMITED -> GapCode.RATE_LIMITED;
            case UNAVAILABLE -> GapCode.UNAVAILABLE;
            case INVALID_RESPONSE -> GapCode.INVALID_RESPONSE;
        };
    }
}
