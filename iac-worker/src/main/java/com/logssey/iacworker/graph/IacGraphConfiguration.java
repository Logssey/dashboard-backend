package com.logssey.iacworker.graph;

import com.logssey.iacworker.analysis.AnalysisEngine;
import com.logssey.iacworker.analysis.AnalyzeRunProcessor;
import com.logssey.iacworker.analysis.AnalyzeRunRepository;
import com.logssey.iacworker.analysis.AwsIamSimulator;
import com.logssey.iacworker.analysis.GraphLoader;

import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.iam.IamClient;

/** 그래프 주소가 있을 때만 보강·분석 처리기를 만든다. 없으면 ENRICH_GRAPH·ANALYZE_RUN 작업은 PENDING 으로 남는다. */
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
        return CloudFrontClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(credentials(properties)).build();
    }

    @Bean(destroyMethod = "close")
    IamClient iacIamClient(IacGraphProperties properties) {
        return IamClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(credentials(properties)).build();
    }

    @Bean
    EnrichGraphProcessor enrichGraphProcessor(Driver driver, CloudFrontClient cloudFront, IacGraphProperties properties,
                                              AttackPathRepository repository) {
        return new EnrichGraphProcessor(new GraphEnricher(driver), new AwsCloudFrontOrigins(cloudFront),
                new FileNodeAddresses(properties.nodeAddressesFile()), repository);
    }

    @Bean
    AnalyzeRunProcessor analyzeRunProcessor(Driver driver, IamClient iam, AnalyzeRunRepository repository) {
        return new AnalyzeRunProcessor(new GraphLoader(driver), new AnalysisEngine(new AwsIamSimulator(iam)), repository);
    }

    /** 읽기 전용 자격 증명 (cloudfront:ListDistributions, iam:SimulateCustomPolicy). 비우면 기본 체인. */
    private static AwsCredentialsProvider credentials(IacGraphProperties properties) {
        return properties.awsProfile() == null || properties.awsProfile().isBlank()
                ? DefaultCredentialsProvider.builder().build()
                : ProfileCredentialsProvider.create(properties.awsProfile());
    }
}
