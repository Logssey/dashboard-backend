package com.logssey.secretworker.detection;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;

class SecretDetectionConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(StubDependencies.class, SecretDetectionConfiguration.class)
            .withPropertyValues(
                    "logssey.secret.detection.fingerprint-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "logssey.secret.detection.fingerprint-key-version=test-v1");

    @Test void metadataOnlyWorkerDoesNotRequireGitleaksOrFingerprintBeans() {
        runner.withPropertyValues("logssey.secret.aws.collection.enabled=true").run(context -> {
            assertNull(context.getStartupFailure());
            assertEquals(0, context.getBeansOfType(SecretFindingNormalizer.class).size());
            assertEquals(0, context.getBeansOfType(SecretFindingRepository.class).size());
        });
        runner.withPropertyValues("logssey.secret.aws.content.enabled=true").run(context -> {
            assertNull(context.getStartupFailure());
            assertEquals(0, context.getBeansOfType(SecretFindingRepository.class).size());
        });
    }

    @Test void eitherContentPipelineGetsOneSharedDetectorAndFingerprintNamespace() {
        for (String[] flags : new String[][]{{"logssey.secret.github.enabled=true"},
                {"logssey.secret.aws.collection.enabled=true", "logssey.secret.aws.content.enabled=true"}}) {
            runner.withPropertyValues(flags).run(context -> {
                assertNull(context.getStartupFailure());
                assertEquals(1, context.getBeansOfType(SecretContentDetector.class).size());
                assertEquals(1, context.getBeansOfType(SecretFindingNormalizer.class).size());
                assertEquals(1, context.getBeansOfType(SecretFindingRepository.class).size());
            });
        }
        runner.withPropertyValues("logssey.secret.github.enabled=true",
                "logssey.secret.aws.collection.enabled=true",
                "logssey.secret.aws.content.enabled=true").run(context -> {
            assertNull(context.getStartupFailure());
            assertEquals(1, context.getBeansOfType(SecretContentDetector.class).size());
            assertEquals(1, context.getBeansOfType(SecretFindingNormalizer.class).size());
            assertEquals(1, context.getBeansOfType(SecretFindingRepository.class).size());
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class StubDependencies {
        @Bean JdbcTemplate jdbcTemplate() { return mock(JdbcTemplate.class); }
        @Bean PlatformTransactionManager transactionManager() { return mock(PlatformTransactionManager.class); }
        @Bean SecretContentDetector testDetector() {
            return new SecretContentDetector() {
                @Override public String engineVersion() { return "test"; }
                @Override public String configHash() { return "0".repeat(64); }
                @Override public GitleaksScanResult scan(byte[] content) {
                    throw new UnsupportedOperationException();
                }
            };
        }
    }
}
