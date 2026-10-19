package com.logssey.iacworker.graph;

import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;

/** 그래프 주소가 있을 때만 보강 처리기를 만든다. 없으면 ENRICH_GRAPH 작업은 PENDING 으로 남는다. */
@Configuration
@EnableConfigurationProperties(IacGraphProperties.class)
@ConditionalOnExpression("!'${logssey.iac.graph.uri:}'.isBlank()")
public class IacGraphConfiguration {

    @Bean(destroyMethod = "close")
    Driver iacGraphDriver(IacGraphProperties properties) {
        return GraphDatabase.driver(properties.uri(), AuthTokens.basic(properties.username(), properties.password()));
    }

    @Bean(destroyMethod = "close")
    CloudFrontClient iacCloudFrontClient(IacGraphProperties properties) {
        var credentials = properties.awsProfile() == null || properties.awsProfile().isBlank()
                ? DefaultCredentialsProvider.builder().build()
                : ProfileCredentialsProvider.create(properties.awsProfile());
        return CloudFrontClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(credentials).build();
    }

    @Bean
    EnrichGraphProcessor enrichGraphProcessor(Driver driver, CloudFrontClient cloudFront, IacGraphProperties properties,
                                              AttackPathRepository repository) {
        return new EnrichGraphProcessor(new GraphEnricher(driver), new AwsCloudFrontOrigins(cloudFront),
                new FileNodeAddresses(properties.nodeAddressesFile()), repository);
    }
}
