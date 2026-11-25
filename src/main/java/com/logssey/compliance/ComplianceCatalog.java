package com.logssey.compliance;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/** 배포물에 고정된 규제 통제와 Prowler Check 관계를 읽는다. */
@Component
public class ComplianceCatalog {

    private final CatalogFile catalog;
    private final Map<String, Framework> frameworks;

    public ComplianceCatalog() {
        try (var input = new ClassPathResource("compliance/catalog.json").getInputStream()) {
            this.catalog = JsonMapper.builder().build().readValue(input, CatalogFile.class);
        } catch (IOException e) {
            throw new IllegalStateException("컴플라이언스 카탈로그를 읽을 수 없습니다.", e);
        }
        if (catalog.schemaVersion() != 1 || catalog.frameworks() == null || catalog.frameworks().isEmpty()) {
            throw new IllegalStateException("지원하지 않는 컴플라이언스 카탈로그입니다.");
        }
        var indexed = new LinkedHashMap<String, Framework>();
        for (var framework : catalog.frameworks()) {
            if (indexed.put(framework.id(), framework) != null) {
                throw new IllegalStateException("중복 규제 프레임워크: " + framework.id());
            }
        }
        this.frameworks = Map.copyOf(indexed);
    }

    public Source source() { return catalog.source(); }
    public List<Framework> frameworks() { return catalog.frameworks(); }
    public Framework framework(String id) { return frameworks.get(id); }

    public record CatalogFile(int schemaVersion, Source source, List<Framework> frameworks) {}
    public record Source(String prowlerVersion, String generatedAt, String generator) {}
    public record Framework(String id, String name, String shortName, String version, String catalogStatus,
                            List<Control> controls) {}
    public record Control(String id, String title, String description, boolean manual, String evaluationMode,
                          boolean manualEvidenceRequired, List<Mapping> mappings) {}
    public record Mapping(String checkId, String provider, String coverage, String review, String failureEffect,
                          String applicability) {
        String key() { return provider.toLowerCase() + ":" + checkId; }
    }
}
