package com.logssey.runtime.ingest;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

class RuntimeRulePackTest {

    private final RuntimeRulePack rulePack = new RuntimeRulePack();

    @Test
    void loadsVersionedRulePackWithUniqueLifecycleGroups() {
        assertThat(rulePack.packVersion()).isEqualTo("1.1.0");
        assertThat(rulePack.rules()).hasSize(24);
        assertThat(rulePack.rules()).extracting(RuntimeRuleDefinition::ruleKey).doesNotHaveDuplicates();
        assertThat(rulePack.rules()).filteredOn(rule -> rule.mode() == RuntimeRuleDefinition.Mode.DETECT)
                .hasSize(12);
        assertThat(rulePack.rules()).filteredOn(rule -> rule.mode() == RuntimeRuleDefinition.Mode.OBSERVE)
                .hasSize(6);
        assertThat(rulePack.rules()).filteredOn(rule -> rule.mode() == RuntimeRuleDefinition.Mode.DRAFT)
                .hasSize(6)
                .allSatisfy(rule -> assertThat(rule.sourceRules()).isEmpty());
    }

    @Test
    void resolvesOfficialAndCustomFalcoAliases() {
        assertThat(rulePack.find("FALCO", "Terminal shell in container"))
                .isEmpty();
        assertThat(rulePack.find("FALCO", "Logssey RUN-001 Container Shell"))
                .get().extracting(RuntimeRuleDefinition::ruleKey).isEqualTo("RUN-001");
        assertThat(rulePack.find("FALCO", "Netcat Remote Code Execution in Container"))
                .get().extracting(RuntimeRuleDefinition::ruleKey).isEqualTo("RUN-016");
        assertThat(rulePack.find("FALCO", "not-supported")).isEmpty();
    }

    @Test
    void rejectsActiveRuleWithoutSensorMapping() {
        Map<String, Object> rule = Map.ofEntries(
                Map.entry("key", "RUN-X"), Map.entry("title", "invalid"),
                Map.entry("version", "1.0.0"), Map.entry("mode", "DETECT"),
                Map.entry("maturity", "STABLE"), Map.entry("eventType", "PROCESS_EXEC"),
                Map.entry("targetType", "PROCESS"), Map.entry("operation", "EXEC"),
                Map.entry("validationProfile", "GENERIC_CONTAINER_PROCESS"),
                Map.entry("sensors", java.util.List.of("FALCO")),
                Map.entry("mitre", java.util.List.of("T1059")),
                Map.entry("noiseBudgetPerMinute", 1), Map.entry("owner", "Runtime Security"),
                Map.entry("sourceRules", Map.of()));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new RuntimeRulePack(Map.of(
                        "schemaVersion", RuntimeRulePack.SCHEMA_VERSION,
                        "packVersion", "test",
                        "rules", java.util.List.of(rule))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("active rule requires a source mapping");
    }
}
