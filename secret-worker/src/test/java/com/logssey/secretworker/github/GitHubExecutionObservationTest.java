package com.logssey.secretworker.github;

import static org.assertj.core.api.Assertions.*;
import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;

class GitHubExecutionObservationTest {
    @Test void actualResponseStatusAndRegisteredOperationAreObservedWithoutSourceOrBody() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String raw = "raw-token-private-repository-provider-body";
        server.createContext("/", exchange -> {
            byte[] body = ("{\"message\":\"" + raw + "\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(403, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            var events = new ArrayList<SafeEvent>();
            ScanExecutionObserver observer = (stage, operation, outcome, status, reason, count, total, duration) ->
                    events.add(new SafeEvent(operation.name(), outcome.name(), status, reason));
            var client = new GitHubRestClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"), HttpClient.newHttpClient()).observed(observer);
            assertThatThrownBy(() -> client.get("repos/private/source/git/blobs/protected-coordinate", raw, 1024)).isInstanceOf(GitHubSourceException.class);
            assertThat(events).containsExactly(new SafeEvent("GITHUB_BLOB_GET", "STARTED", null, null),
                    new SafeEvent("GITHUB_BLOB_GET", "FAILED", 403, "ACCESS_DENIED"));
            assertThat(events.toString()).doesNotContain(raw, "private/source", "protected-coordinate");
        } finally { server.stop(0); }
    }

    @Test void observedCopiesKeepConnectionsSeparate() {
        var left = new ArrayList<String>();
        var right = new ArrayList<String>();
        var original = new GitHubRestClient(URI.create("http://127.0.0.1:1/"), HttpClient.newHttpClient());
        var a = original.observed((stage, operation, outcome, status, reason, count, total, duration) -> left.add(outcome.name()));
        var b = original.observed((stage, operation, outcome, status, reason, count, total, duration) -> right.add(outcome.name()));
        assertThatThrownBy(() -> a.get("repos/a/git/ref/heads/main", "synthetic", 1024)).isInstanceOf(GitHubSourceException.class);
        assertThat(left).containsExactly("STARTED", "FAILED");
        assertThat(right).isEmpty();
        assertThatThrownBy(() -> b.get("repos/b/git/ref/heads/main", "synthetic", 1024)).isInstanceOf(GitHubSourceException.class);
        assertThat(left).hasSize(2);
        assertThat(right).containsExactly("STARTED", "FAILED");
    }
    private record SafeEvent(String operation, String outcome, Integer httpStatus, String reason) {}
}
