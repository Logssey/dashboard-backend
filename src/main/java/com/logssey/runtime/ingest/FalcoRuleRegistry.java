package com.logssey.runtime.ingest;

import java.util.Optional;

import org.springframework.stereotype.Component;

/** Immutable allow-list translating sensor rule names to the dashboard's stable rule contract. */
@Component
public class FalcoRuleRegistry {

    private final RuntimeRulePack rulePack;

    public FalcoRuleRegistry(RuntimeRulePack rulePack) {
        this.rulePack = rulePack;
    }

    public Optional<RuntimeRuleDefinition> find(String sourceRule) {
        return rulePack.find("FALCO", sourceRule);
    }
}
