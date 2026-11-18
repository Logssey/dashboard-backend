package com.logssey.compliance;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/** 조건부 서비스의 실제 사용 여부를 추론할 수 있는 Prowler 결과를 선언적으로 관리한다. */
@Component
public class ComplianceServiceUsageEvidenceCatalog {

    private static final Set<String> SUPPORTED_RESULTS = Set.of("PASS", "FAIL");

    private final Map<String, Map<String, Set<String>>> rulesByService;

    public ComplianceServiceUsageEvidenceCatalog(ProwlerScopeCatalog scopeCatalog) {
        final EvidenceFile file;
        try (var input = new ClassPathResource("compliance/service-usage-evidence.json").getInputStream()) {
            file = JsonMapper.builder().build().readValue(input, EvidenceFile.class);
        } catch (IOException e) {
            throw new IllegalStateException("서비스 사용 증거 카탈로그를 읽을 수 없습니다.", e);
        }
        if (file.schemaVersion() != 1 || !scopeCatalog.version().equals(file.prowlerVersion())
                || file.services() == null || file.services().isEmpty()) {
            throw new IllegalStateException("지원하지 않는 서비스 사용 증거 카탈로그입니다.");
        }

        var indexedServices = new LinkedHashMap<String, Map<String, Set<String>>>();
        for (var servicePolicy : file.services()) {
            String service = servicePolicy.service();
            if (service == null || !scopeCatalog.supportsService(service)
                    || servicePolicy.rules() == null || servicePolicy.rules().isEmpty()) {
                throw new IllegalStateException("잘못된 서비스 사용 증거 정책: " + service);
            }
            var indexedRules = new LinkedHashMap<String, Set<String>>();
            for (var rule : servicePolicy.rules()) {
                if (rule.checkId() == null || !scopeCatalog.supportsCheck(rule.checkId())
                        || !service.equals(scopeCatalog.serviceForCheck(rule.checkId()))
                        || rule.acceptedResults() == null || rule.acceptedResults().isEmpty()
                        || !SUPPORTED_RESULTS.containsAll(rule.acceptedResults())) {
                    throw new IllegalStateException("잘못된 서비스 사용 증거 규칙: " + rule.checkId());
                }
                if (indexedRules.put(rule.checkId(), Set.copyOf(rule.acceptedResults())) != null) {
                    throw new IllegalStateException("중복 서비스 사용 증거 규칙: " + rule.checkId());
                }
            }
            if (indexedServices.put(service, Map.copyOf(indexedRules)) != null) {
                throw new IllegalStateException("중복 서비스 사용 증거 정책: " + service);
            }
        }
        this.rulesByService = Map.copyOf(indexedServices);
    }

    boolean governs(String service) {
        return rulesByService.containsKey(service);
    }

    boolean isUsageEvidence(String service, String checkId, String result) {
        return rulesByService.getOrDefault(service, Map.of())
                .getOrDefault(checkId, Set.of())
                .contains(result);
    }

    Set<String> governedServices() {
        return rulesByService.keySet();
    }

    record EvidenceFile(int schemaVersion, String prowlerVersion, List<ServicePolicy> services) {}
    record ServicePolicy(String service, List<EvidenceRule> rules) {}
    record EvidenceRule(String checkId, List<String> acceptedResults) {}
}
