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
    GitHubCollector gitHubCollector(
            @Value("${logssey.secret.github.app-id}") long appId,
            @Value("${logssey.secret.github.installation-id}") long installationId,
            @Value("${logssey.secret.github.private-key-path}") String privateKeyPath) {
        GitHubRestClient api = new GitHubRestClient();
        GitHubAppCredentials credentials = new GitHubAppCredentials(appId, installationId,
                Path.of(privateKeyPath));
        return new GitHubCollector(api, new GitHubAppTokenProvider(credentials, api));
    }

    @Bean
    GitHubSecretJobProcessor gitHubSecretJobProcessor(
            JdbcTemplate jdbc,
            GitHubCollector collector,
            SecretContentDetector detector,
            SecretFindingRepository findings,
            SecretFindingNormalizer normalizer,
            AwsValidationService validator,
            SecretValidationAttemptRepository attempts,
            SecretJobProperties jobs,
            com.logssey.secretworker.validation.GitHubPatValidator githubValidator,
            org.springframework.beans.factory.ObjectProvider<GitHubRepositoryAccessSink>
                    accessSinks) {
        return new GitHubSecretJobProcessor(
                jdbc,
                collector,
                detector,
                findings,
                normalizer,
                validator,
                attempts,
                jobs,
                githubValidator,
                accessSinks.orderedStream().toList());
    }
}
