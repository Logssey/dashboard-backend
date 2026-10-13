package com.logssey.secretworker.aws;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import com.logssey.secretworker.SecretJobProperties;

@Configuration
@ConditionalOnProperty(name = "logssey.secret.aws.collection.enabled", havingValue = "true")
class AwsCollectorConfiguration {
    @Bean(destroyMethod = "close")
    AwsIamGateway awsIamGateway(@Value("${logssey.secret.aws.collection.profile}") String profile) {
        return new AwsSdkIamGateway(profile);
    }

    @Bean
    AwsIamCollector awsIamCollector(AwsIamGateway gateway) {
        return new AwsIamCollector(gateway);
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
                                                AwsIamMetadataRepository metadata,
                                                SecretJobProperties jobs,
                                                @Value("${logssey.secret.aws.collection.profile}") String profile) {
        return new AwsSecretJobProcessor(jdbc, collector, metadata, jobs, profile);
    }
}
