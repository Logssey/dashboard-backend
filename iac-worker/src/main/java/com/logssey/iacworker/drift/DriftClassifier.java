package com.logssey.iacworker.drift;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import tools.jackson.databind.JsonNode;

/**
 * 드리프트 분류 (FR-S1, rule-spec drift.*). 코드 밖에서 바뀐 속성 이름만 보고 값은 다루지 않는다 (SR-4).
 *
 * 노이즈로 빼는 것 (지금 prod plan 에서 확인한 것):
 *   - 시간이 지나면 저절로 바뀌는 값 (RDS latest_restorable_time)
 *   - 다른 리소스로 관리하는 값이 비쳐 보이는 것 (aws_iam_role 의 inline_policy·managed_policy_arns)
 *   - 쿠버네티스가 붙이는 볼륨 (aws_instance 의 ebs_block_device, EBS CSI)
 */
public final class DriftClassifier {

    private static final Set<String> NOISE = Set.of("latest_restorable_time");
    private static final Map<String, Set<String>> NOISE_BY_TYPE = Map.of(
            "aws_iam_role", Set.of("inline_policy", "managed_policy_arns"),
            "aws_instance", Set.of("ebs_block_device"));
    private static final Set<String> TAGS = Set.of("tags", "tags_all");
    /** 경로·노출에 직접 영향을 주는 종류: 보안 그룹, IAM, DNS, LB, 네트워크, 엣지. */
    private static final List<String> HIGH_PREFIXES = List.of("aws_security_group", "aws_vpc_security_group_",
            "aws_iam_", "aws_route53_", "aws_lb", "aws_alb", "aws_route", "aws_network_acl", "aws_subnet", "aws_vpc",
            "aws_internet_gateway", "aws_nat_gateway", "aws_eip", "aws_cloudfront_", "aws_wafv2_",
            "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block", "aws_acm_");

    private DriftClassifier() {
    }

    /** ruleId 가 null 이면 노이즈만 바뀐 것. */
    public record Drift(String address, String type, String action, String ruleId, List<String> attributes) {
    }

    public static Drift classify(JsonNode resourceDrift) {
        String address = resourceDrift.path("address").asString();
        String type = resourceDrift.path("type").asString();
        JsonNode change = resourceDrift.path("change");
        String action = change.path("actions").path(0).asString("update");
        if (action.equals("delete")) {
            return new Drift(address, type, action, high(type) ? "drift.high" : "drift.medium", List.of());
        }
        Set<String> changed = new TreeSet<>();
        JsonNode before = change.path("before");
        JsonNode after = change.path("after");
        before.propertyNames().forEach(changed::add);
        after.propertyNames().forEach(changed::add);
        changed.removeIf(name -> before.path(name).equals(after.path(name)));
        changed.removeAll(NOISE);
        changed.removeAll(NOISE_BY_TYPE.getOrDefault(type, Set.of()));
        if (changed.isEmpty()) {
            return new Drift(address, type, action, null, List.of());
        }
        String ruleId = TAGS.containsAll(changed) ? "drift.low" : high(type) ? "drift.high" : "drift.medium";
        return new Drift(address, type, action, ruleId, new ArrayList<>(changed));
    }

    private static boolean high(String type) {
        return HIGH_PREFIXES.stream().anyMatch(type::startsWith);
    }
}
