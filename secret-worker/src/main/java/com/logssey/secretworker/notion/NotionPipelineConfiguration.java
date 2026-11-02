package com.logssey.secretworker.notion;

import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.GitHubPatValidator;
import com.logssey.secretworker.validation.NotionTokenValidator;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;
import java.nio.file.Path;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/** Opt-in like the GitHub pipeline. The collector token is a file path; its value never enters the DB. */
@Configuration
@ConditionalOnProperty(name = "logssey.secret.notion.enabled", havingValue = "true")
class NotionPipelineConfiguration {

    @Bean
    NotionPageClient notionPageClient(@Value("${logssey.secret.notion.token-path}") String tokenPath) {
        if (tokenPath == null || tokenPath.isBlank()) {
            throw new IllegalArgumentException("SECRET_NOTION_TOKEN_PATH is required");
        }
        return new NotionPageClient(Path.of(tokenPath));
    }

    @Bean
    NotionSecretJobProcessor notionSecretJobProcessor(
            JdbcTemplate jdbc,
            NotionPageClient client,
            SecretContentDetector detector,
            SecretFindingRepository findings,
            SecretFindingNormalizer normalizer,
            AwsValidationService awsValidator,
            SecretValidationAttemptRepository attempts,
            SecretJobProperties jobs,
            GitHubPatValidator githubValidator,
            NotionTokenValidator notionValidator,
            ObjectProvider<NotionPageAccessSink> accessSinks) {
        return new NotionSecretJobProcessor(jdbc, client, detector, findings, normalizer, awsValidator,
                attempts, jobs, githubValidator, notionValidator, accessSinks.orderedStream().toList());
    }
}
