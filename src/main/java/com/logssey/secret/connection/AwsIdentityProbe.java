package com.logssey.secret.connection;

import java.time.Duration;

import org.springframework.stereotype.Component;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.StsException;

/** Identity-only AWS probe: STS GetCallerIdentity does not enumerate or read secret values. */
@Component
class AwsIdentityProbe {
    ConnectionProbeResult probe(String profile, String expectedAccount) {
        try (var credentials = ProfileCredentialsProvider.create(profile);
             var client = StsClient.builder().credentialsProvider(credentials)
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
