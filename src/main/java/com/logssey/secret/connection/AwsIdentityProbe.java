package com.logssey.secret.connection;

import java.time.Duration;
import com.logssey.secret.aws.SecretAwsSourceCredentials;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.StsException;

/** Identity-only AWS probe: STS GetCallerIdentity does not enumerate or read secret values. */
@Component
class AwsIdentityProbe {
    private final String credentialsMode;
    private final String credentialsFile;

    AwsIdentityProbe(String credentialsMode) { this(credentialsMode, ""); }

    @org.springframework.beans.factory.annotation.Autowired
    AwsIdentityProbe(@Value("${logssey.secret.aws.collection.credentials-mode:PROFILE}") String credentialsMode,
            @Value("${logssey.secret.aws.collection.credentials-file:}") String credentialsFile) {
        if (!"PROFILE".equals(credentialsMode) && !"WORKLOAD".equals(credentialsMode))
            throw new IllegalArgumentException("AWS_CREDENTIALS_MODE_INVALID");
        this.credentialsMode = credentialsMode;
        this.credentialsFile = credentialsFile;
    }

    ConnectionProbeResult probe(String profile, String expectedAccount) {
        if (!"PROFILE".equals(credentialsMode)) return ConnectionProbeResult.unavailable("AWS_UNAVAILABLE");
        return probeIdentity("PROFILE", profile, expectedAccount);
    }

    ConnectionProbeResult probeWorkload(String expectedAccount) {
        if (!"WORKLOAD".equals(credentialsMode)) return ConnectionProbeResult.unavailable("AWS_UNAVAILABLE");
        return probeIdentity("WORKLOAD", "", expectedAccount);
    }

    private ConnectionProbeResult probeIdentity(String mode, String profile, String expectedAccount) {
        try (var credentials = SecretAwsSourceCredentials.fromConfiguration(mode, profile, credentialsFile);
             var client = StsClient.builder().credentialsProvider(credentials::resolveCredentials)
                     .region(Region.US_EAST_1)
                     .httpClientBuilder(UrlConnectionHttpClient.builder())
                     .overrideConfiguration(ClientOverrideConfiguration.builder()
                             .apiCallTimeout(Duration.ofSeconds(10))
                             .apiCallAttemptTimeout(Duration.ofSeconds(6)).build())
                     .build()) {
            String actualAccount = client.getCallerIdentity().account();
            if (actualAccount == null || !actualAccount.equals(expectedAccount)) {
                return ConnectionProbeResult.failed("AWS_ACCOUNT_MISMATCH");
            }
            return ConnectionProbeResult.connected();
        } catch (StsException e) {
            int status = e.statusCode();
            if (status == 429 || "Throttling".equals(e.awsErrorDetails() == null
                    ? null : e.awsErrorDetails().errorCode())) {
                return ConnectionProbeResult.unavailable("AWS_RATE_LIMITED");
            }
            if (status == 401 || status == 403) return ConnectionProbeResult.failed("AWS_ACCESS_DENIED");
            return ConnectionProbeResult.unavailable("AWS_UNAVAILABLE");
        } catch (SdkClientException | IllegalArgumentException e) {
            return ConnectionProbeResult.unavailable("AWS_UNAVAILABLE");
        } catch (RuntimeException e) {
            // SDK exception messages can include profile details; never log or return them.
            return ConnectionProbeResult.unavailable("AWS_UNAVAILABLE");
        }
    }
}
