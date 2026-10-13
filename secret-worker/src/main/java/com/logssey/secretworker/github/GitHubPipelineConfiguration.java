package com.logssey.secretworker.github;

import java.nio.file.Path;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksDetector;
import com.logssey.secretworker.detector.SecretContentDetector;

@Configuration
@ConditionalOnProperty(name = "logssey.secret.github.enabled", havingValue = "true")
class GitHubPipelineConfiguration {

    @Bean
    GitHubCollector gitHubCollector(@Value("${logssey.secret.github.app-id}") long appId,
                                    @Value("${logssey.secret.github.installation-id}") long installationId,
                                    @Value("${logssey.secret.github.private-key-path}") String privateKeyPath) {
        GitHubRestClient api = new GitHubRestClient();
        GitHubAppCredentials credentials = new GitHubAppCredentials(appId, installationId,
                Path.of(privateKeyPath));
        return new GitHubCollector(api, new GitHubAppTokenProvider(credentials, api));
    }

    @Bean
    GitleaksDetector gitleaksDetector(@Value("${logssey.secret.github.gitleaks-path}") String executable) {
        return new GitleaksDetector(Path.of(executable));
    }

    @Bean
    SecretFindingRepository secretFindingRepository(
            JdbcTemplate jdbc, PlatformTransactionManager transactionManager,
            @Value("${logssey.secret.github.fingerprint-key}") String fingerprintKey,
            @Value("${logssey.secret.github.fingerprint-key-version}") String keyVersion) {
        return new SecretFindingRepository(jdbc, new TransactionTemplate(transactionManager),
                SecretFindingNormalizer.fromBase64(fingerprintKey, keyVersion));
    }

    @Bean
    GitHubSecretJobProcessor gitHubSecretJobProcessor(JdbcTemplate jdbc, GitHubCollector collector,
            SecretContentDetector detector, SecretFindingRepository findings) {
        return new GitHubSecretJobProcessor(jdbc, collector, detector, findings);
    }
}
