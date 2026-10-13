package com.logssey.secretworker.aws.content;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** An exact AWS value is read only after a separate runtime opt-in, then consumed in memory. */
public final class AwsContentCollector {
    public static final int DEFAULT_MAX_BYTES = 256 * 1024;
    public static final int ABSOLUTE_MAX_BYTES = 1024 * 1024;

    public enum Status { SUCCEEDED, FAILED }
    public enum GapCode {
        CONTENT_READ_DISABLED, ACCESS_DENIED, NOT_FOUND, RATE_LIMITED, SOURCE_UNAVAILABLE,
        OBJECT_TOO_LARGE, NON_TEXT, CONSUMER_FAILED
    }

    /** No ARN, parameter name, bucket, object key, or value is present in this record. */
    public record Source(AwsContentScope.Kind kind, int byteCount) { }
    public record Result(Status status, int objectCount, long byteCount, List<GapCode> gaps) { }

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
                sink.accept(new Source(scope.kind(), content.length), content);
            } catch (RuntimeException error) {
                return failed(GapCode.CONSUMER_FAILED);
            }
            return new Result(Status.SUCCEEDED, 1, content.length, List.of());
        } finally {
            Arrays.fill(content, (byte) 0);
        }
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
