package com.logssey.secret.response;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/** Shared bounded response reader. Error bodies are cancelled before buffering. */
final class SecretGuideHttpBody implements HttpResponse.BodySubscriber<byte[]> {
    static final int MAX_BYTES = 8_192;
    static final class ResponseTooLarge extends RuntimeException { }

    private final CompletableFuture<byte[]> body = new CompletableFuture<>();
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private final boolean read;
    private final boolean oversized;
    private Flow.Subscription subscription;

    SecretGuideHttpBody(boolean read, long contentLength) {
        this.read = read;
        this.oversized = contentLength > MAX_BYTES;
    }

    @Override public CompletionStage<byte[]> getBody() { return body; }

    @Override public void onSubscribe(Flow.Subscription value) {
        subscription = value;
        if (!read || oversized) {
            value.cancel();
            if (read && oversized) body.completeExceptionally(new ResponseTooLarge());
            else body.complete(new byte[0]);
        } else value.request(1);
    }

    @Override public void onNext(List<ByteBuffer> buffers) {
        for (ByteBuffer buffer : buffers) {
            if (buffer.remaining() > MAX_BYTES - bytes.size()) {
                subscription.cancel();
                body.completeExceptionally(new ResponseTooLarge());
                return;
            }
            byte[] chunk = new byte[buffer.remaining()];
            buffer.get(chunk);
            bytes.writeBytes(chunk);
        }
        subscription.request(1);
    }

    @Override public void onError(Throwable failure) { body.completeExceptionally(failure); }
    @Override public void onComplete() { body.complete(bytes.toByteArray()); }
}
