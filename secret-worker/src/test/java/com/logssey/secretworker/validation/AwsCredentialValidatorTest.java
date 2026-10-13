package com.logssey.secretworker.validation;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.sts.model.StsException;

class AwsCredentialValidatorTest {
    private static final String ACCESS_KEY = "AKIAFAKE123456789012";
    private static final String SECRET = "synthetic-secret-not-usable";
    private static final Instant NOW = Instant.parse("2026-10-14T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void disabledDoesNotCallStsEvenForCompleteKey() {
        AtomicInteger calls = new AtomicInteger();
        AwsCredentialValidator validator = new AwsCredentialValidator(false, CLOCK, key -> calls.incrementAndGet());

        AwsValidationResult result = validator.validate(pair());

        assertThat(result.status()).isEqualTo(AwsValidationResult.Status.UNCHECKED);
        assertThat(result.reason()).isEqualTo(AwsValidationResult.Reason.DISABLED);
        assertThat(result.checkedAt()).isNull();
        assertThat(result.evaluatedAt()).isEqualTo(NOW);
        assertThat(calls).hasValue(0);
    }

    @Test
    void incompletePairsAndTemporaryKeyWithoutSessionTokenAreUnchecked() {
        AtomicInteger calls = new AtomicInteger();
        AwsCredentialValidator validator = new AwsCredentialValidator(true, CLOCK, key -> calls.incrementAndGet());

        assertThat(validator.validate(new AwsKeyMaterial(ACCESS_KEY, null, null)).reason())
                .isEqualTo(AwsValidationResult.Reason.INCOMPLETE_PAIR);
        assertThat(validator.validate(new AwsKeyMaterial(null, SECRET, null)).status())
                .isEqualTo(AwsValidationResult.Status.UNCHECKED);
        assertThat(validator.validate(new AwsKeyMaterial("ASIAFAKE123456789012", SECRET, null)).reason())
                .isEqualTo(AwsValidationResult.Reason.MISSING_SESSION_TOKEN);
        assertThat(validator.validate(null).status()).isEqualTo(AwsValidationResult.Status.UNCHECKED);
        assertThat(calls).hasValue(0);
    }

    @Test
    void successfulIdentityCallIsValidAndRecordsAttemptTime() {
        AtomicInteger calls = new AtomicInteger();
        AwsCredentialValidator validator = new AwsCredentialValidator(true, CLOCK, key -> calls.incrementAndGet());

        AwsValidationResult result = validator.validate(pair());

        assertThat(result.status()).isEqualTo(AwsValidationResult.Status.VALID);
        assertThat(result.reason()).isEqualTo(AwsValidationResult.Reason.AUTHENTICATED);
        assertThat(result.checkedAt()).isEqualTo(NOW);
        assertThat(result.method()).isEqualTo(AwsValidationResult.METHOD);
        assertThat(result.version()).isEqualTo(AwsValidationResult.VERSION);
        assertThat(calls).hasValue(1);
    }

    @Test
    void onlySpecificStsErrorsProveInvalidity() {
        assertThat(withError("InvalidClientTokenId", 403).status())
                .isEqualTo(AwsValidationResult.Status.INVALID);
        assertThat(withError("InvalidClientTokenId", 403).reason())
                .isEqualTo(AwsValidationResult.Reason.INVALID_ACCESS_KEY);
        assertThat(withError("ExpiredToken", 403).reason())
                .isEqualTo(AwsValidationResult.Reason.EXPIRED_SESSION);
    }

    @Test
    void ambiguousAuthorizationRateLimitsAndNetworkFailuresRemainUnknownWithoutRawMessages() {
        assertThat(withError("AccessDenied", 403).reason())
                .isEqualTo(AwsValidationResult.Reason.ACCESS_AMBIGUOUS);
        assertThat(withError("SignatureDoesNotMatch", 403).reason())
                .isEqualTo(AwsValidationResult.Reason.SIGNATURE_AMBIGUOUS);
        assertThat(withError("SignatureDoesNotMatch", 403).status())
                .isEqualTo(AwsValidationResult.Status.UNKNOWN);
        assertThat(withError("Throttling", 429).reason())
                .isEqualTo(AwsValidationResult.Reason.RATE_LIMITED);
        assertThat(withError("InternalFailure", 500).reason())
                .isEqualTo(AwsValidationResult.Reason.PROVIDER_UNAVAILABLE);

        AwsValidationResult network = new AwsCredentialValidator(true, CLOCK,
                key -> { throw new IllegalStateException("provider echoed " + SECRET); }).validate(pair());
        assertThat(network.status()).isEqualTo(AwsValidationResult.Status.UNKNOWN);
        assertThat(network.reason()).isEqualTo(AwsValidationResult.Reason.CLIENT_FAILURE);
        assertThat(network.toString()).doesNotContain(SECRET, ACCESS_KEY);
        assertThat(pair().toString()).doesNotContain(SECRET, ACCESS_KEY);
    }

    @Test
    void sdkSignsLocalStsRequestWithSuppliedKeyInsteadOfAmbientProfile() throws IOException {
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = ("<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                    + "<GetCallerIdentityResult><Arn>arn:aws:iam::000000000000:user/test</Arn>"
                    + "<UserId>test</UserId><Account>000000000000</Account></GetCallerIdentityResult>"
                    + "<ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>"
                    + "</GetCallerIdentityResponse>").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/xml");
            exchange.sendResponseHeaders(200, response.length);
            try (var output = exchange.getResponseBody()) {
                output.write(response);
            }
        });
        server.start();
        try {
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            AwsValidationResult result = new AwsCredentialValidator(true, CLOCK, new AwsStsCaller(endpoint))
                    .validate(pair());

            assertThat(result.status()).isEqualTo(AwsValidationResult.Status.VALID);
            assertThat(authorization.get()).contains("Credential=" + ACCESS_KEY + "/");
            assertThat(body.get()).contains("Action=GetCallerIdentity").doesNotContain(SECRET);
        } finally {
            server.stop(0);
        }
    }

    private static AwsKeyMaterial pair() {
        return new AwsKeyMaterial(ACCESS_KEY, SECRET, null);
    }

    private static AwsValidationResult withError(String code, int status) {
        return new AwsCredentialValidator(true, CLOCK, key -> {
            throw StsException.builder().statusCode(status).awsErrorDetails(AwsErrorDetails.builder()
                    .errorCode(code).errorMessage("provider echoed " + SECRET).build()).build();
        }).validate(pair());
    }
}
