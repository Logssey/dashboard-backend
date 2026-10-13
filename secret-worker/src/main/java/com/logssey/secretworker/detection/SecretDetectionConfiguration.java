package com.logssey.secretworker.detection;

import java.nio.file.Path;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.logssey.secretworker.detector.GitleaksDetector;
import com.logssey.secretworker.detector.SecretContentDetector;

/** One detector and fingerprint namespace shared by explicitly enabled content pipelines. */
@Configuration(proxyBeanMethods = false)
@Conditional(SecretDetectionConfiguration.Enabled.class)
public class SecretDetectionConfiguration {
    static final class Enabled implements Condition {
        @Override public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Environment environment = context.getEnvironment();
            return Boolean.parseBoolean(environment.getProperty("logssey.secret.github.enabled", "false"))
                    || (Boolean.parseBoolean(environment.getProperty("logssey.secret.aws.collection.enabled", "false"))
                    && Boolean.parseBoolean(environment.getProperty("logssey.secret.aws.content.enabled", "false")));
        }
    }

    @Bean
    @ConditionalOnMissingBean(SecretContentDetector.class)
    SecretContentDetector secretContentDetector(
            @Value("${logssey.secret.detection.gitleaks-path}") String executable) {
        return new GitleaksDetector(Path.of(executable));
    }

    @Bean
    SecretFindingNormalizer secretFindingNormalizer(
            @Value("${logssey.secret.detection.fingerprint-key}") String fingerprintKey,
            @Value("${logssey.secret.detection.fingerprint-key-version}") String keyVersion) {
        return SecretFindingNormalizer.fromBase64(fingerprintKey, keyVersion);
    }

    @Bean
    SecretFindingRepository secretFindingRepository(JdbcTemplate jdbc,
            PlatformTransactionManager transactionManager, SecretFindingNormalizer normalizer) {
        return new SecretFindingRepository(jdbc, new TransactionTemplate(transactionManager), normalizer);
    }
}
