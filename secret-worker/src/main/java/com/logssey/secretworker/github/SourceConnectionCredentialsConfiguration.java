package com.logssey.secretworker.github;

import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secret.connection.core.*;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
class SourceConnectionCredentialsConfiguration {
    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(name = "logssey.secret.connections.enabled", havingValue = "true")
    ConnectionCredentialStore sourceConnectionCredentialStore(
            @Value("${logssey.secret.connections.aws-region:ap-northeast-1}") String region,
            @Value(
                            "${logssey.secret.connections.secret-prefix:logssey/dashboard/source-credentials/}")
                    String prefix,
            @Value("${logssey.secret.aws.collection.credentials-mode:PROFILE}") String mode,
            @Value("${logssey.secret.aws.collection.profile:}") String profile,
            @Value("${logssey.secret.aws.collection.credentials-file:}") String file) {
        return new SecretsManagerConnectionCredentialStore(
                SecretAwsSourceCredentials.fromConfiguration(mode, profile, file), region, prefix);
    }

    @Bean
    SourceConnectionCredentialResolver sourceConnectionCredentialResolver(
            JdbcTemplate jdbc,
            ObjectProvider<ConnectionCredentialStore> store,
            @Value("${logssey.secret.github.app-id:0}") long app,
            @Value("${logssey.secret.github.installation-id:0}") long installation,
            @Value("${logssey.secret.github.private-key-path:}") String path) {
        return new SourceConnectionCredentialResolver(
                jdbc, store.getIfAvailable(), app, installation, path);
    }
}
