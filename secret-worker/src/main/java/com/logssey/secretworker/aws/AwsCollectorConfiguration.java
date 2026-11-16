package com.logssey.secretworker.aws;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.aws.content.AwsContentPipeline;
import com.logssey.secretworker.aws.metadata.AwsMetadataCollector;
import com.logssey.secretworker.aws.metadata.AwsSdkMetadataPageClient;

import com.logssey.secret.aws.SecretAwsSourceCredentials;

@Configuration
@ConditionalOnProperty(name = "logssey.secret.aws.collection.enabled", havingValue = "true")
class AwsCollectorConfiguration {
    @Bean(destroyMethod = "close")
    AwsIamGateway awsIamGateway(SecretAwsSourceCredentials credentials) {
        return new AwsSdkIamGateway(credentials);
    }

    @Bean
    AwsIamCollector awsIamCollector(AwsIamGateway gateway) {
        return new AwsIamCollector(gateway);
    }

    @Bean(destroyMethod = "close")
    SecretAwsSourceCredentials awsSourceCredentials(
            @Value("${logssey.secret.aws.collection.credentials-mode:PROFILE}") String mode,
            @Value("${logssey.secret.aws.collection.profile}") String profile,
            @Value("${logssey.secret.aws.collection.credentials-file:}") String file) {
        return SecretAwsSourceCredentials.fromConfiguration(mode, profile, file);
    }

    @Bean
    AwsMetadataCollector awsMetadataCollector(SecretAwsSourceCredentials credentials) {
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
                                                ObjectProvider<AwsContentPipeline> content,
                                                SecretAwsSourceCredentials credentials) {
        return new AwsSecretJobProcessor(jdbc, collector, additional, gateway,
                metadata, jobs, credentials, content.getIfAvailable());
    }
}
