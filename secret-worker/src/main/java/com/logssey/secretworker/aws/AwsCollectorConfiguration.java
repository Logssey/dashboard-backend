package com.logssey.secretworker.aws;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.aws.metadata.AwsMetadataCollector;
import com.logssey.secretworker.aws.metadata.AwsSdkMetadataPageClient;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;

@Configuration
@ConditionalOnProperty(name = "logssey.secret.aws.collection.enabled", havingValue = "true")
class AwsCollectorConfiguration {
    @Bean(destroyMethod = "close")
    AwsIamGateway awsIamGateway(ProfileCredentialsProvider credentials) {
        return new AwsSdkIamGateway(credentials);
    }

    @Bean
    AwsIamCollector awsIamCollector(AwsIamGateway gateway) {
        return new AwsIamCollector(gateway);
    }

    @Bean(destroyMethod = "close")
    ProfileCredentialsProvider awsProfileCredentials(
            @Value("${logssey.secret.aws.collection.profile}") String profile) {
        if (profile == null || !profile.matches("[A-Za-z0-9._-]{1,100}")) {
            throw new IllegalArgumentException("AWS_PROFILE_REQUIRED");
        }
        return ProfileCredentialsProvider.create(profile);
    }

    @Bean
    AwsMetadataCollector awsMetadataCollector(ProfileCredentialsProvider credentials) {
        return new AwsMetadataCollector(new AwsSdkMetadataPageClient(credentials));
    }

    @Bean
    AwsMetadataIdentity awsMetadataIdentity(
            @Value("${logssey.secret.aws.collection.identity-key}") String key,
            @Value("${logssey.secret.aws.collection.identity-key-version}") String version) {
        return AwsMetadataIdentity.fromBase64(key, version);
    }

    @Bean
    AwsIamMetadataRepository awsIamMetadataRepository(JdbcTemplate jdbc,
                                                      AwsMetadataIdentity identity) {
        return new AwsIamMetadataRepository(jdbc, identity);
    }

    @Bean
    AwsSecretJobProcessor awsSecretJobProcessor(JdbcTemplate jdbc, AwsIamCollector collector,
                                                AwsMetadataCollector additional,
                                                AwsIamGateway gateway,
                                                AwsIamMetadataRepository metadata,
                                                SecretJobProperties jobs,
                                                @Value("${logssey.secret.aws.collection.profile}") String profile) {
        return new AwsSecretJobProcessor(jdbc, collector, additional, gateway,
                metadata, jobs, profile);
    }
}
