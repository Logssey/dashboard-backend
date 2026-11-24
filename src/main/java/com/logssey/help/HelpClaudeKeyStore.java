package com.logssey.help;

import java.time.Duration;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import com.logssey.secret.aws.SecretAwsSourceCredentials;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/**
 * Reads the Claude key from Secrets Manager with the API's own role session, the same secret and settings the
 * report and secret-guide parts use (design doc 17). This is the only class in the help package that touches AWS,
 * and the only outside class it uses is the AWS credential helper; it never reads secret findings or keys data.
 * A good key is kept for ten minutes and a failure for one minute, so status checks do not call AWS each time.
 */
final class HelpClaudeKeyStore implements Supplier<String> {

    static final Duration KEEP_KEY = Duration.ofMinutes(10);
    static final Duration KEEP_FAILURE = Duration.ofMinutes(1);
    private static final String SECRET_ID = "[A-Za-z0-9/_+=.@:-]{1,512}";
    private static final String REGION = "[a-z]{2}(?:-[a-z]+)+-[0-9]+";

    private final Supplier<String> reader;
    private final LongSupplier clock;
    private String key;
    private long readAt;
    private boolean failed;

    HelpClaudeKeyStore(Supplier<String> reader, LongSupplier clock) {
        this.reader = reader;
        this.clock = clock;
    }

    /** Null when the secret id or region is missing or malformed: the provider then reports KEY_MISSING. */
    static HelpClaudeKeyStore secretsManager(String secretId, String region, String mode, String profile, String file) {
        if (secretId == null || !secretId.matches(SECRET_ID) || region == null || !region.matches(REGION)) return null;
        return new HelpClaudeKeyStore(() -> read(secretId, region, mode, profile, file), System::nanoTime);
    }

    /** The current key, or null when it could not be read. Never throws and never logs the value. */
    @Override
    public synchronized String get() {
        long now = clock.getAsLong();
        if (readAt != 0 && now - readAt < (failed ? KEEP_FAILURE : KEEP_KEY).toNanos()) return failed ? null : key;
        String value;
        try {
            value = reader.get();
        } catch (RuntimeException unavailable) {
            value = null;
        }
        boolean usable = value != null && !value.isBlank() && value.length() <= 4_096
                && value.strip().chars().allMatch(c -> c >= 0x21 && c <= 0x7e);
        key = usable ? value.strip() : null;
        failed = !usable;
        readAt = now == 0 ? 1 : now;
        return key;
    }

    private static String read(String secretId, String region, String mode, String profile, String file) {
        protectLogging();
        try (var credentials = SecretAwsSourceCredentials.fromConfiguration(mode, profile, file);
             var client = SecretsManagerClient.builder().credentialsProvider(credentials).region(Region.of(region))
                     .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(15))
                             .apiCallAttemptTimeout(Duration.ofSeconds(8)))
                     .build()) {
            return client.getSecretValue(r -> r.secretId(secretId).versionStage("AWSCURRENT")).secretString();
        }
    }

    /** Do not read the key while request/response body logging is on. */
    private static void protectLogging() {
        for (String logger : List.of("software.amazon.awssdk.request", "software.amazon.awssdk.response",
                "org.apache.hc.client5.http.wire", "org.apache.http.wire")) {
            if (org.slf4j.LoggerFactory.getLogger(logger).isDebugEnabled()) {
                throw new IllegalStateException("KEY_STORE_LOGGING");
            }
        }
    }
}
