package com.logssey.runtime.query.dto;

import java.util.List;

public record RuntimeRuleCatalogResponse(
        String packVersion,
        List<RuleItem> rules) {

    public record RuleItem(
            String ruleKey,
            String title,
            String version,
            String eventType,
            String targetType,
            String operation,
            String mode,
            String maturity,
            List<String> sensors,
            List<String> mitreTechniques,
            int noiseBudgetPerMinute,
            String owner) {
    }
}
