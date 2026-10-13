package com.logssey.secretworker.aws.content;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;

/** Merely creating these beans makes no AWS value calls. Both opt-ins are required. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = {"logssey.secret.aws.collection.enabled",
        "logssey.secret.aws.content.enabled"}, havingValue = "true")
class AwsContentConfiguration {
    @Bean
    AwsContentCollector awsContentCollector(ProfileCredentialsProvider credentials) {
        return new AwsContentCollector(new AwsSdkContentReader(credentials));
    }

    @Bean
    AwsContentPipeline awsContentPipeline(AwsContentCollector collector,
            SecretContentDetector detector, SecretFindingNormalizer normalizer,
            SecretFindingRepository findings, AwsValidationService validator,
            SecretValidationAttemptRepository attempts) {
        return new AwsContentPipeline(collector, detector, normalizer, findings, validator, attempts);
    }
}
