package com.logssey.secretworker.usage;

import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secretworker.aws.AwsMetadataIdentity;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

/** Usage can run independently; creating read credentials never enables source collection. */
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(name="logssey.secret.usage.cloudtrail-enabled",havingValue="true")
public class UsageConfiguration {
    @Configuration(proxyBeanMethods=false)
    @Conditional(IndependentManagementConfigured.class)
    static class IndependentManagementIdentity {
        @Bean(destroyMethod="close")
        SecretAwsSourceCredentials usageAwsSourceCredentials(
                @Value("${logssey.secret.aws.collection.credentials-mode:PROFILE}")String mode,
                @Value("${logssey.secret.aws.collection.profile:}")String profile,
                @Value("${logssey.secret.aws.collection.credentials-file:}")String file){return SecretAwsSourceCredentials.fromConfiguration(mode,profile,file);}
        @Bean
        @Conditional(MetadataConfigured.class)
        AwsMetadataIdentity usageAwsMetadataIdentity(
                @Value("${logssey.secret.aws.collection.identity-key}")String key,
                @Value("${logssey.secret.aws.collection.identity-key-version}")String version){return AwsMetadataIdentity.fromBase64(key,version);}
    }
    @Bean
    @Conditional(IndependentNormalizerConfigured.class)
    SecretFindingNormalizer usageFindingNormalizer(
            @Value("${logssey.secret.detection.fingerprint-key}")String key,
            @Value("${logssey.secret.detection.fingerprint-key-version}")String version){return SecretFindingNormalizer.fromBase64(key,version);}
    static boolean configured(Environment e,String key,String version){return !e.getProperty(key,"").isBlank()&&!e.getProperty(version,"").isBlank();}
    static final class IndependentManagementConfigured implements Condition {
        @Override public boolean matches(ConditionContext c,AnnotatedTypeMetadata m){var e=c.getEnvironment();return e.getProperty("logssey.secret.usage.cloudtrail-enabled",Boolean.class,false)&&!e.getProperty("logssey.secret.aws.collection.enabled",Boolean.class,false);}
    }
    static final class MetadataConfigured implements Condition {
        @Override public boolean matches(ConditionContext c,AnnotatedTypeMetadata m){return configured(c.getEnvironment(),"logssey.secret.aws.collection.identity-key","logssey.secret.aws.collection.identity-key-version");}
    }
    static final class IndependentNormalizerConfigured implements Condition {
        @Override public boolean matches(ConditionContext c,AnnotatedTypeMetadata m){var e=c.getEnvironment();
            boolean existing=e.getProperty("logssey.secret.github.enabled",Boolean.class,false)
                    ||e.getProperty("logssey.secret.notion.collection.enabled",Boolean.class,false)
                    ||e.getProperty("logssey.secret.aws.collection.enabled",Boolean.class,false)&&e.getProperty("logssey.secret.aws.content.enabled",Boolean.class,false);
            return !existing&&configured(e,"logssey.secret.detection.fingerprint-key","logssey.secret.detection.fingerprint-key-version");
        }
    }
}
