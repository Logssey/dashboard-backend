package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

class SecretGuideProviderConfigurationTest {
    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withBean(SecretAiCallBudget.class, () -> mock(SecretAiCallBudget.class))
            .withUserConfiguration(Providers.class);

    @Test void defaultsToExactlyOneClaudeAdapterAndGroqRequiresExplicitSelection() {
        context.run(value -> {
            assertThat(value).hasSingleBean(SecretGuideProvider.class);
            assertThat(value.getBean(SecretGuideProvider.class)).isInstanceOf(ClaudeSecretGuideProvider.class);
            assertThat(value.getBean(SecretGuideProvider.class).configurationReason()).isEqualTo("DISABLED");
        });
        context.withPropertyValues("logssey.secret.guide.provider=groq").run(value -> {
            assertThat(value).hasSingleBean(SecretGuideProvider.class);
            assertThat(value.getBean(SecretGuideProvider.class)).isInstanceOf(GroqSecretGuideProvider.class);
        });
    }

    @Test void productionConstructionRequiresTheSharedBudgetDependency() {
        new ApplicationContextRunner().withUserConfiguration(Providers.class).run(value -> assertThat(value).hasFailed());
    }

    @Configuration(proxyBeanMethods = false)
    @Import({ClaudeSecretGuideProvider.class, GroqSecretGuideProvider.class})
    static class Providers { }
}
