package com.logssey.secretworker.usage;
import static org.assertj.core.api.Assertions.*;
import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secretworker.aws.AwsMetadataIdentity;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.*;
class UsageConfigurationTest {
    @Configuration(proxyBeanMethods=false)
    @ComponentScan(basePackageClasses=UsageConfiguration.class,excludeFilters=@ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,classes={UsageObservationExecutor.class,UsageObservationScheduler.class,UsageObservationPoller.class}))
    static class ScanUsageConfiguration { }
    static final String KEY=java.util.Base64.getEncoder().encodeToString(new byte[32]);
    final ApplicationContextRunner runner=new ApplicationContextRunner().withUserConfiguration(UsageConfiguration.class).withPropertyValues(
        "logssey.secret.usage.cloudtrail-enabled=true","logssey.secret.aws.collection.credentials-mode=PROFILE","logssey.secret.aws.collection.profile=fixture",
        "logssey.secret.aws.collection.identity-key="+KEY,"logssey.secret.aws.collection.identity-key-version=fixture",
        "logssey.secret.detection.fingerprint-key="+KEY,"logssey.secret.detection.fingerprint-key-version=fixture");
    @Test void usageAloneRegistersReadIdentityAndProtectionWithoutEnablingCollectors(){runner.run(c->{assertThat(c).hasNotFailed().hasSingleBean(SecretAwsSourceCredentials.class).hasSingleBean(AwsMetadataIdentity.class).hasSingleBean(SecretFindingNormalizer.class);assertThat(c.getBean(SecretAwsSourceCredentials.class).authRef()).isEqualTo("aws-profile:fixture");assertThat(c).doesNotHaveBean("awsIamGateway").doesNotHaveBean("secretContentDetector");});}
    @Test void disabledUsageCreatesNoProvidersOrProtectionBeans(){runner.withPropertyValues("logssey.secret.usage.cloudtrail-enabled=false").run(c->assertThat(c).hasNotFailed().doesNotHaveBean(SecretAwsSourceCredentials.class).doesNotHaveBean(AwsMetadataIdentity.class).doesNotHaveBean(SecretFindingNormalizer.class));}
    @Test void existingAwsContentPipelineRemainsTheOnlyOwnerOfItsBeans(){runner.withPropertyValues("logssey.secret.aws.collection.enabled=true","logssey.secret.aws.content.enabled=true")
        .withBean(SecretAwsSourceCredentials.class,()->SecretAwsSourceCredentials.profile("existing"))
        .withBean(AwsMetadataIdentity.class,()->new AwsMetadataIdentity(new byte[32],"existing"))
        .withBean(SecretFindingNormalizer.class,()->new SecretFindingNormalizer(new byte[32],"existing"))
        .run(c->{assertThat(c).hasNotFailed().hasSingleBean(SecretAwsSourceCredentials.class).hasSingleBean(AwsMetadataIdentity.class).hasSingleBean(SecretFindingNormalizer.class);assertThat(c).doesNotHaveBean("usageAwsSourceCredentials").doesNotHaveBean("usageAwsMetadataIdentity").doesNotHaveBean("usageFindingNormalizer");});}
    @Test void existingGithubNormalizerCanShareTheIndependentUsageReadIdentity(){runner.withPropertyValues("logssey.secret.github.enabled=true").withBean(SecretFindingNormalizer.class,()->new SecretFindingNormalizer(new byte[32],"existing"))
        .run(c->{assertThat(c).hasNotFailed().hasSingleBean(SecretAwsSourceCredentials.class).hasSingleBean(SecretFindingNormalizer.class);assertThat(c).doesNotHaveBean("usageFindingNormalizer");});}
    @Test void missingOptionalProtectionDoesNotInventAKeyBinding(){runner.withPropertyValues("logssey.secret.aws.collection.identity-key=","logssey.secret.detection.fingerprint-key=").run(c->assertThat(c).hasNotFailed().hasSingleBean(SecretAwsSourceCredentials.class).doesNotHaveBean(AwsMetadataIdentity.class).doesNotHaveBean(SecretFindingNormalizer.class));}
    @Test void defaultDisabledComponentScanCannotDiscoverAndActivateNestedCredentialsConfiguration(){new ApplicationContextRunner().withUserConfiguration(ScanUsageConfiguration.class).run(c->assertThat(c).hasNotFailed().doesNotHaveBean(SecretAwsSourceCredentials.class).doesNotHaveBean(AwsMetadataIdentity.class).doesNotHaveBean(SecretFindingNormalizer.class));}
    @Test void enabledComponentScanStillRegistersTheIndependentIdentityExactlyOnce(){runner.withUserConfiguration(ScanUsageConfiguration.class).run(c->assertThat(c).hasNotFailed().hasSingleBean(SecretAwsSourceCredentials.class).hasSingleBean(AwsMetadataIdentity.class).hasSingleBean(SecretFindingNormalizer.class));}
}
