package com.logssey.secretworker.aws;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.StsClient;

import static org.assertj.core.api.Assertions.assertThat;

class AwsSdkIamGatewayTest {
    private static final String SYNTHETIC_ID = "AKIAABCDEFGHIJKLMNOP";
    private final List<String> actions = new ArrayList<>();
    private HttpServer server;

    @AfterEach
    void closeServer() {
        if (server != null) server.stop(0);
    }

    @Test
    void callsOnlyExplicitReadMethodsAgainstFakeEndpoint() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::respond);
        server.start();
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        var credentials = StaticCredentialsProvider.create(
                AwsBasicCredentials.create("TESTACCESSKEY", "TESTSECRETKEY"));
        try (var sts = StsClient.builder().region(Region.US_EAST_1)
                .credentialsProvider(credentials).endpointOverride(endpoint).build();
             var iam = IamClient.builder().region(Region.AWS_GLOBAL)
                     .credentialsProvider(credentials).endpointOverride(endpoint).build();
             var gateway = new AwsSdkIamGateway(sts, iam)) {
            assertThat(gateway.accountId()).isEqualTo("123456789012");
            assertThat(gateway.rootAccessKeyCount()).isZero();
            assertThat(gateway.users(null).items()).containsExactly("alice");
            var keys = gateway.accessKeys("alice", null).items();
            assertThat(keys).hasSize(1);
            assertThat(keys.getFirst().id()).isEqualTo(SYNTHETIC_ID);
            assertThat(keys.getFirst().status()).isEqualTo("Active");
            assertThat(gateway.lastUsed(SYNTHETIC_ID).at())
                    .isEqualTo(Instant.parse("2026-10-01T00:00:00Z"));
        }
        assertThat(actions).containsExactly("GetCallerIdentity", "GetAccountSummary", "ListUsers",
                "ListAccessKeys", "GetAccessKeyLastUsed");
    }

    private void respond(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String action = action(body);
        actions.add(action);
        String xml = switch (action) {
            case "GetCallerIdentity" -> """
                    <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                      <GetCallerIdentityResult><Account>123456789012</Account>
                        <Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>TESTUSER</UserId>
                      </GetCallerIdentityResult><ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>
                    </GetCallerIdentityResponse>
                    """;
            case "ListUsers" -> """
                    <ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
                      <ListUsersResult><Users><member><UserName>alice</UserName>
                        <UserId>TESTUSER</UserId><Arn>arn:aws:iam::123456789012:user/alice</Arn>
                        <Path>/</Path><CreateDate>2026-01-01T00:00:00Z</CreateDate>
                      </member></Users><IsTruncated>false</IsTruncated></ListUsersResult>
                      <ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>
                    </ListUsersResponse>
                    """;
            case "GetAccountSummary" -> """
                    <GetAccountSummaryResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
                      <GetAccountSummaryResult><SummaryMap><entry>
                        <key>AccountAccessKeysPresent</key><value>0</value>
                      </entry></SummaryMap></GetAccountSummaryResult>
                      <ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>
                    </GetAccountSummaryResponse>
                    """;
            case "ListAccessKeys" -> """
                    <ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
                      <ListAccessKeysResult><AccessKeyMetadata><member>
                        <UserName>alice</UserName><AccessKeyId>%s</AccessKeyId>
                        <Status>Active</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate>
                      </member></AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult>
                      <ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>
                    </ListAccessKeysResponse>
                    """.formatted(SYNTHETIC_ID);
            case "GetAccessKeyLastUsed" -> """
                    <GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
                      <GetAccessKeyLastUsedResult><UserName>alice</UserName>
                        <AccessKeyLastUsed><LastUsedDate>2026-10-01T00:00:00Z</LastUsedDate>
                          <ServiceName>Amazon S3</ServiceName><Region>ap-northeast-1</Region>
                        </AccessKeyLastUsed></GetAccessKeyLastUsedResult>
                      <ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>
                    </GetAccessKeyLastUsedResponse>
                    """;
            default -> throw new AssertionError("Unexpected AWS API action");
        };
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/xml; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static String action(String body) {
        for (String value : List.of("GetCallerIdentity", "GetAccountSummary",
                "ListUsers", "ListAccessKeys",
                "GetAccessKeyLastUsed")) {
            if (body.contains("Action=" + value)) return value;
        }
        throw new AssertionError("Unexpected AWS API action");
    }
}
