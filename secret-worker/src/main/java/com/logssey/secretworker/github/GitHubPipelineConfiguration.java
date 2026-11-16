package com.logssey.secretworker.github;

import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Path;

@Configuration
@ConditionalOnProperty(name = "logssey.secret.github.enabled", havingValue = "true")
class GitHubPipelineConfiguration {

    @Bean
    GitHubSecretJobProcessor gitHubSecretJobProcessor(
            JdbcTemplate jdbc,
            com.logssey.secret.connection.core.SourceConnectionCredentialResolver credentials,
            SecretContentDetector detector,
            SecretFindingRepository findings,
            SecretFindingNormalizer normalizer,
            AwsValidationService validator,
            SecretValidationAttemptRepository attempts,
            SecretJobProperties jobs,
            com.logssey.secretworker.validation.GitHubPatValidator githubValidator,
            com.logssey.secretworker.validation.NotionTokenValidator notionValidator,
            org.springframework.beans.factory.ObjectProvider<GitHubRepositoryAccessSink>
                    accessSinks) {
        return new GitHubSecretJobProcessor(
                jdbc,
                null,
                detector,
                findings,
                normalizer,
                validator,
                attempts,
                jobs,
                githubValidator,
                accessSinks.orderedStream().toList(),
                notionValidator,
                (connectionId, scopeVersion) -> {
                    var material = credentials.resolve(connectionId, scopeVersion);
                    var api = new GitHubRestClient();
                    return new GitHubCollector(api, new GitHubAppTokenProvider(material.appId(),
                            material.installationId(), material.privateKey(), api, java.time.Clock.systemUTC()));
                });
    }
}
