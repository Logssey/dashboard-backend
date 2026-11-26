package com.logssey.secretworker.aws.content;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.logssey.secretworker.SecretJobFailure;

/** An exact AWS value is read only after a separate runtime opt-in, then consumed in memory. */
public final class AwsContentCollector {
    public static final int DEFAULT_MAX_BYTES = 256 * 1024;
    public static final int ABSOLUTE_MAX_BYTES = 1024 * 1024;

    public enum Status { SUCCEEDED, PARTIAL, FAILED }
    public enum GapCode {
        CONTENT_READ_DISABLED, ACCESS_DENIED, NOT_FOUND, RATE_LIMITED, SOURCE_UNAVAILABLE,
        OBJECT_TOO_LARGE, NON_TEXT, CONSUMER_FAILED, OBJECT_LIMIT, TOTAL_BYTES_LIMIT,
        PAGINATION_LOOP, INVALID_OBJECT_KEY
    }

    /** No ARN, parameter name, bucket, object key, or value is present in this record. */
    public record Source(AwsContentScope.Kind kind, int byteCount, String objectKey) { }
    public record Result(Status status, int objectCount, long byteCount, List<GapCode> gaps) { }

    public AwsContentCollector observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) {
        return new AwsContentCollector(reader.observed(observer));
    }

    @FunctionalInterface
    public interface ContentSink {
        /** Must finish processing synchronously; content is zeroed as soon as this returns. */
        void accept(Source source, byte[] utf8Content);
    }

    private final AwsContentReader reader;

    public AwsContentCollector(AwsContentReader reader) {
        this.reader = Objects.requireNonNull(reader);
    }

    public Result collect(AwsContentScope scope, boolean valueReadEnabled, int maxBytes,
                          ContentSink sink) {
        Objects.requireNonNull(scope);
        Objects.requireNonNull(sink);
        if (maxBytes < 1 || maxBytes > ABSOLUTE_MAX_BYTES) {
            throw new IllegalArgumentException("Invalid AWS content byte limit");
        }
        if (!valueReadEnabled) return failed(GapCode.CONTENT_READ_DISABLED);
        if (scope.kind() == AwsContentScope.Kind.S3_PREFIX)
            return collectPrefix(scope, maxBytes, sink);

        byte[] content;
        try {
            content = Objects.requireNonNull(reader.read(scope, maxBytes));
        } catch (AwsContentReader.ReadFailure error) {
            return failed(map(error.code()));
        } catch (RuntimeException error) {
            // SDK and consumer exception messages may embed value bytes or resource names.
            return failed(GapCode.SOURCE_UNAVAILABLE);
        }
        try {
            if (content.length > maxBytes) return failed(GapCode.OBJECT_TOO_LARGE);
            if (!isText(content)) return failed(GapCode.NON_TEXT);
            try {
                sink.accept(new Source(scope.kind(), content.length, scope.objectKey()), content);
            } catch (SecretJobFailure error) {
                // A lost lease is a worker ownership failure, never an ordinary scope gap.
                throw error;
            } catch (RuntimeException error) {
                return failed(GapCode.CONSUMER_FAILED);
            }
            return new Result(Status.SUCCEEDED, 1, content.length, List.of());
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /** Check absence through the approved prefix listing, never infer it from a denied HEAD. */
    public Result recheckObject(AwsContentScope prefix, String objectKey, boolean enabled,
                                int maxBytes, ContentSink sink) {
        var target = prefix.child(objectKey);
        if (!enabled) return failed(GapCode.CONTENT_READ_DISABLED);
        if (maxBytes < 1 || maxBytes > ABSOLUTE_MAX_BYTES) throw new IllegalArgumentException("Invalid AWS content byte limit");
        String token = null;
        var seenTokens = new java.util.HashSet<String>();
        int entries = 0;
        for (int page = 0; page < 100; page++) {
            AwsContentReader.ObjectPage batch;
            try { batch = reader.list(prefix, token); }
            catch (AwsContentReader.ReadFailure error) { return failed(map(error.code())); }
            catch (RuntimeException error) { return failed(GapCode.SOURCE_UNAVAILABLE); }
            for (String key : batch.keys()) {
                if (++entries > 10000) return failed(GapCode.OBJECT_LIMIT);
                if (key == null || !key.startsWith(prefix.objectKey())) return failed(GapCode.INVALID_OBJECT_KEY);
                if (key.equals(objectKey)) return collect(target, true, maxBytes, sink);
            }
            token = batch.nextToken();
            if (token == null) return new Result(Status.SUCCEEDED, 0, 0, List.of());
            if (!seenTokens.add(token)) return failed(GapCode.PAGINATION_LOOP);
        }
        return failed(GapCode.OBJECT_LIMIT);
    }

    private Result collectPrefix(AwsContentScope prefix, int maxBytes, ContentSink sink) {
        var gaps = new java.util.LinkedHashSet<GapCode>();
        var tokens = new java.util.HashSet<String>();
        var keys = new java.util.HashSet<String>();
        String token = null;
        int objects = 0, entries = 0;
        long bytes = 0;
        boolean listed = false;
        outer: for (int page = 0; page < 100; page++) {
            AwsContentReader.ObjectPage batch;
            try { batch = reader.list(prefix, token); listed = true; }
            catch (AwsContentReader.ReadFailure error) { gaps.add(map(error.code())); break; }
            catch (RuntimeException error) { gaps.add(GapCode.SOURCE_UNAVAILABLE); break; }
            for (String key : batch.keys()) {
                if (++entries > 10000) { gaps.add(GapCode.OBJECT_LIMIT); break outer; }
                if (key != null && key.startsWith(prefix.objectKey()) && key.endsWith("/")) continue;
                AwsContentScope child;
                try { child = prefix.child(key); prefix.childSourceRef(1L, key); }
                catch (IllegalArgumentException error) { gaps.add(GapCode.INVALID_OBJECT_KEY); continue; }
                if (!keys.add(key)) continue;
                int remaining = (int) Math.min(maxBytes, 16L * 1024 * 1024 - bytes);
                if (remaining < 1) { gaps.add(GapCode.TOTAL_BYTES_LIMIT); break outer; }
                Result item = collect(child, true, remaining, sink);
                objects += item.objectCount(); bytes += item.byteCount(); gaps.addAll(item.gaps());
            }
            token = batch.nextToken();
            if (token == null) break;
            if (!tokens.add(token)) { gaps.add(GapCode.PAGINATION_LOOP); break; }
            if (page == 99) gaps.add(GapCode.OBJECT_LIMIT);
        }
        return new Result(gaps.isEmpty() ? Status.SUCCEEDED : listed ? Status.PARTIAL : Status.FAILED,
                objects, bytes, List.copyOf(gaps));
    }

    private static boolean isText(byte[] content) {
        for (byte value : content) {
            int unsigned = value & 0xff;
            if (unsigned == 0 || unsigned < 32 && unsigned != 9 && unsigned != 10 && unsigned != 13
                    || unsigned == 127) return false;
        }
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(content));
            return true;
        } catch (CharacterCodingException error) {
            return false;
        }
    }

    private static Result failed(GapCode code) {
        return new Result(Status.FAILED, 0, 0, List.of(code));
    }

    private static GapCode map(AwsContentReader.FailureCode code) {
        return switch (code) {
            case ACCESS_DENIED -> GapCode.ACCESS_DENIED;
            case NOT_FOUND -> GapCode.NOT_FOUND;
            case RATE_LIMITED -> GapCode.RATE_LIMITED;
            case UNAVAILABLE -> GapCode.SOURCE_UNAVAILABLE;
            case TOO_LARGE -> GapCode.OBJECT_TOO_LARGE;
            case NON_TEXT -> GapCode.NON_TEXT;
        };
    }
}
