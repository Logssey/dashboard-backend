package com.logssey.secret.connection;

import static org.assertj.core.api.Assertions.*;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NotionAuthProbeTest {
    @TempDir Path directory;

    @Test void authenticatesOnlyAgainstSelfAndDropsProfileAndCredentialData() throws Exception {
        var calls=new AtomicInteger();
        String token="ntn_"+"A".repeat(46);
        Path file=directory.resolve("token.txt"); Files.writeString(file,token);
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/v1/users/me",exchange->{
            calls.incrementAndGet();
            assertThat(exchange.getRequestMethod()).isEqualTo("GET");
            assertThat(exchange.getRequestHeaders().getFirst("Authorization")).isEqualTo("Bearer "+token);
            assertThat(exchange.getRequestHeaders().getFirst("Notion-Version")).isEqualTo("2026-03-11");
            byte[] body=("{\"object\":\"user\",\"id\":\"11111111-2222-3333-4444-555555555555\","
                    +"\"type\":\"bot\",\"name\":\"private-profile\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();
        }); server.start();
        try {
            var probe=probe(file,server,Duration.ofSeconds(2));
            var result=probe.probe("notion-internal:default");
            assertThat(result.status()).isEqualTo("CONNECTED");
            assertThat(result.toString()).doesNotContain(token,"private-profile",file.toString());
            assertThat(calls).hasValue(1);
            assertThat(probe.probe("notion-internal:other").reasonCode()).isEqualTo("INVALID_APPROVED_SCOPE");
            assertThat(calls).hasValue(1);
        } finally {server.stop(0);}
    }

    @Test void rateLimitsAndRedirectsReturnSafeResultsWithoutFollowingAnotherEndpoint() throws Exception {
        Path file=directory.resolve("token.txt");Files.writeString(file,"ntn_"+"B".repeat(46));
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var status=new AtomicInteger(429);var calls=new AtomicInteger();var redirected=new AtomicInteger();
        server.createContext("/v1/users/me",exchange->{calls.incrementAndGet();
            exchange.getResponseHeaders().set("Location","/private");
            exchange.sendResponseHeaders(status.get(),-1);exchange.close();});
        server.createContext("/private",exchange->{redirected.incrementAndGet();exchange.sendResponseHeaders(200,-1);exchange.close();});
        server.start();
        try {
            var probe=probe(file,server,Duration.ofSeconds(2));
            assertThat(probe.probe("notion-internal:default").reasonCode()).isEqualTo("NOTION_RATE_LIMITED");
            status.set(401);
            assertThat(probe.probe("notion-internal:default").reasonCode()).isEqualTo("NOTION_ACCESS_DENIED");
            status.set(302);
            assertThat(probe.probe("notion-internal:default").status()).isEqualTo("UNAVAILABLE");
            assertThat(calls).hasValue(3);assertThat(redirected).hasValue(0);
        } finally {server.stop(0);}
    }

    @Test void bodyDelayIsBoundedAndMissingConfigurationNeverSends() throws Exception {
        Path file=directory.resolve("token.txt");Files.writeString(file,"ntn_"+"C".repeat(46));
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var calls=new AtomicInteger();
        server.createContext("/v1/users/me",exchange->{calls.incrementAndGet();
            exchange.sendResponseHeaders(200,100);
            try {Thread.sleep(500);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}
            exchange.close();});server.start();
        try {
            URI uri=URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/v1/users/me");
            assertThat(new NotionAuthProbe(false,file,uri,Duration.ofMillis(100))
                    .probe("notion-internal:default").reasonCode()).isEqualTo("NOTION_COLLECTION_DISABLED");
            assertThat(calls).hasValue(0);
            long start=System.nanoTime();
            assertThat(probe(file,server,Duration.ofMillis(100)).probe("notion-internal:default").status()).isEqualTo("UNAVAILABLE");
            assertThat(Duration.ofNanos(System.nanoTime()-start)).isLessThan(Duration.ofSeconds(3));
        } finally {server.stop(0);}
    }

    private static NotionAuthProbe probe(Path file,HttpServer server,Duration timeout) {
        return new NotionAuthProbe(true,file,URI.create("http://127.0.0.1:"
                +server.getAddress().getPort()+"/v1/users/me"),timeout);
    }
}
