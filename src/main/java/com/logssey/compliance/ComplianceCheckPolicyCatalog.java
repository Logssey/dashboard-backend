package com.logssey.compliance;

import static com.logssey.compliance.ComplianceDtos.ImprovementGuide;
import static com.logssey.compliance.ComplianceTargetDtos.AssessmentProfile;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/** Prowler Check의 적용 조건과 사용자용 개선 가이드를 버전 고정 데이터로 관리한다. */
@Component
public class ComplianceCheckPolicyCatalog {

    static final String CONTROL_FAIL = "CONTROL_FAIL";
    static final String REVIEW_ONLY = "REVIEW_ONLY";

    private final PolicyFile file;
    private final Map<String, CheckPolicy> policies;

    public ComplianceCheckPolicyCatalog() {
        try (var input = new ClassPathResource("compliance/check-policies.json").getInputStream()) {
            this.file = JsonMapper.builder().build().readValue(input, PolicyFile.class);
        } catch (IOException e) {
            throw new IllegalStateException("컴플라이언스 Check 정책을 읽을 수 없습니다.", e);
        }
        if (file.schemaVersion() != 1 || file.policyVersion() == null || file.policyVersion().isBlank()
                || file.prowlerVersion() == null || file.prowlerVersion().isBlank() || file.policies() == null) {
            throw new IllegalStateException("지원하지 않는 컴플라이언스 Check 정책입니다.");
        }
        var indexed = new LinkedHashMap<String, CheckPolicy>();
        for (var policy : file.policies()) {
            if (policy.checkId() == null || policy.checkId().isBlank()
                    || !List.of(CONTROL_FAIL, REVIEW_ONLY).contains(policy.assessmentEffect())) {
                throw new IllegalStateException("잘못된 컴플라이언스 Check 정책: " + policy.checkId());
            }
            if (REVIEW_ONLY.equals(policy.assessmentEffect()) && Stream.of(
                    policy.applicabilityType(), policy.applicabilityKey(),
                    policy.disposition(), policy.expectedState(), policy.applicability(),
                    policy.changeImpact(), policy.verification(), policy.rollback(), policy.sourceUrl())
                    .anyMatch(value -> value == null || value.isBlank())) {
                throw new IllegalStateException("검토형 Check 정책의 개선 가이드가 불완전합니다: " + policy.checkId());
            }
            if (policy.sourceUrl() != null && !policy.sourceUrl().equals(
                    "https://hub.prowler.com/check/" + policy.checkId())) {
                throw new IllegalStateException("Check 정책 출처가 Prowler Check와 일치하지 않습니다: " + policy.checkId());
            }
            String key = key(policy.provider(), policy.checkId());
            if (indexed.put(key, policy) != null) {
                throw new IllegalStateException("중복 컴플라이언스 Check 정책: " + key);
            }
        }
        this.policies = Map.copyOf(indexed);
    }

    ApplicabilityStatus applicability(String provider, String checkId, AssessmentProfile profile,
                                      Set<String> inferredServices) {
        var policy = policy(provider, checkId);
        return switch (valueOr(policy.applicabilityType(), "ALWAYS")) {
            case "ALWAYS" -> ApplicabilityStatus.APPLICABLE;
            case "SERVICE_USAGE" -> serviceApplicability(policy.applicabilityKey(), profile, inferredServices);
            case "REQUIREMENT" -> requirementApplicability(policy.applicabilityKey(), profile);
            case "RESOURCE_CONTEXT" -> ApplicabilityStatus.UNKNOWN;
            default -> throw new IllegalStateException("지원하지 않는 Check 적용성 규칙: " + policy.checkId());
        };
    }

    CheckPolicy policy(String provider, String checkId) {
        return policies.getOrDefault(key(provider, checkId), CheckPolicy.defaultPolicy(provider, checkId));
    }

    ImprovementGuide guide(String provider, String checkId, String fallbackRecommendation) {
        var policy = policy(provider, checkId);
        String fallbackExpectedState = valueOr(plainGuideText(fallbackRecommendation),
                "점검 기준 원문에서 요구하는 목표 상태를 확인한 뒤 현재 설정과 비교합니다.");
        return new ImprovementGuide(
                valueOr(policy.disposition(), "DIRECT_ACTION"),
                valueOr(policy.expectedState(), fallbackExpectedState),
                valueOr(policy.applicability(), "이 Check가 가리키는 자산이 실제 점검 범위에 포함되는지 확인한 뒤 조치합니다."),
                valueOr(policy.changeImpact(), "변경 전 의존 서비스와 접근 경로를 확인하고 기존 설정을 기록합니다."),
                valueOr(policy.verification(), "동일 범위에서 Check를 다시 실행하고 대상 자산의 결과가 PASS인지 확인합니다."),
                valueOr(policy.rollback(), "영향이 발생하면 기록해 둔 이전 설정으로 복원한 뒤 동일 범위를 다시 점검합니다."),
                valueOr(policy.sourceUrl(), "https://hub.prowler.com/check/" + checkId),
                file.prowlerVersion());
    }

    int size() { return policies.size(); }
    String version() { return file.policyVersion(); }
    Set<String> checkIds() {
        return policies.values().stream().map(CheckPolicy::checkId).collect(Collectors.toUnmodifiableSet());
    }
    Set<String> serviceUsageKeys() {
        return policies.values().stream()
                .filter(policy -> "SERVICE_USAGE".equals(policy.applicabilityType()))
                .map(CheckPolicy::applicabilityKey)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static String key(String provider, String checkId) {
        String normalizedProvider = provider == null || provider.isBlank() ? "aws" : provider;
        return normalizedProvider.toLowerCase(Locale.ROOT) + ":" + checkId;
    }

    private static ApplicabilityStatus serviceApplicability(String service, AssessmentProfile profile,
                                                            Set<String> inferredServices) {
        String status = profile.serviceUsage().getOrDefault(service, "UNKNOWN");
        if ("USED".equals(status) || inferredServices.contains(service)) return ApplicabilityStatus.APPLICABLE;
        if ("NOT_USED".equals(status)) return ApplicabilityStatus.NOT_APPLICABLE;
        return ApplicabilityStatus.UNKNOWN;
    }

    private static ApplicabilityStatus requirementApplicability(String requirement, AssessmentProfile profile) {
        return switch (profile.requirements().getOrDefault(requirement, "UNKNOWN")) {
            case "REQUIRED" -> ApplicabilityStatus.APPLICABLE;
            case "NOT_REQUIRED" -> ApplicabilityStatus.NOT_APPLICABLE;
            default -> ApplicabilityStatus.UNKNOWN;
        };
    }

    private static String valueOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Prowler remediation의 간단한 Markdown 표기를 UI·HTML 보고서용 일반 문장으로 바꾼다. */
    private static String plainGuideText(String value) {
        if (value == null || value.isBlank()) return value;
        return value
                .replaceAll("\\[([^\\]]+)]\\([^)]+\\)", "$1")
                .replaceAll("(?i)prowler\\s+guide", "점검 기준 원문")
                .replaceAll("(?i)prowler", "점검 기준")
                .replace("**", "")
                .replace("__", "")
                .replace("`", "")
                .replaceAll("\\s*\\R\\s*", " ")
                .replaceAll(":\\s+-\\s+", ": ")
                .replaceAll("\\s+-\\s+", " · ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    record PolicyFile(int schemaVersion, String policyVersion, String prowlerVersion,
                      List<CheckPolicy> policies) {}

    enum ApplicabilityStatus { APPLICABLE, NOT_APPLICABLE, UNKNOWN }

    record CheckPolicy(String checkId, String provider, String assessmentEffect,
                       String applicabilityType, String applicabilityKey, String disposition,
                       String expectedState, String applicability, String changeImpact,
                       String verification, String rollback, String sourceUrl) {
        static CheckPolicy defaultPolicy(String provider, String checkId) {
            return new CheckPolicy(checkId, provider, CONTROL_FAIL, "ALWAYS", "ALWAYS", "DIRECT_ACTION",
                    null, null, null, null, null, null);
        }
    }
}
