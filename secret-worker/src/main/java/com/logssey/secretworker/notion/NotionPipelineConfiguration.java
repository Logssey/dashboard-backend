package com.logssey.secretworker.notion;

import com.logssey.secret.notion.SecretNotionSourceCredentials;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.*;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "logssey.secret.notion.collection.enabled", havingValue = "true")
class NotionPipelineConfiguration {
  @Bean
  SecretNotionSourceCredentials notionSourceCredentials(
      @Value("${logssey.secret.notion.token-file:}") String tokenFile) {
    if (tokenFile == null || tokenFile.isBlank())
      throw new IllegalArgumentException("NOTION_SOURCE_CREDENTIALS_UNAVAILABLE");
    return SecretNotionSourceCredentials.file(Path.of(tokenFile));
  }

  @Bean
  NotionCollector notionCollector(SecretNotionSourceCredentials credentials) {
    return new NotionCollector(new NotionPageClient(credentials::token));
  }

  @Bean
  NotionSecretJobProcessor notionSecretJobProcessor(
      JdbcTemplate jdbc,
      NotionCollector collector,
      SecretNotionSourceCredentials credentials,
      SecretContentDetector detector,
      SecretFindingRepository findings,
      SecretFindingNormalizer normalizer,
      SecretValidationAttemptRepository attempts,
      AwsValidationService aws,
      GitHubPatValidator github,
      NotionTokenValidator notion,
      SecretJobProperties jobs) {
    return new NotionSecretJobProcessor(
        jdbc,
        collector,
        credentials,
        detector,
        findings,
        normalizer,
        attempts,
        aws,
        github,
        notion,
        jobs);
  }
}
