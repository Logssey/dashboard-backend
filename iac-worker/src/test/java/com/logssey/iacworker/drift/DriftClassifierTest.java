package com.logssey.iacworker.drift;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class DriftClassifierTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @Test
    void classifiesByResourceTypeAndKeepsOnlyAttributeNames() {
        var dns = classify("aws_route53_record", "{\"alias\":[{\"name\":\"a\"}],\"ttl\":60}", "{\"alias\":[{\"name\":\"b\"}],\"ttl\":60}");
        assertThat(dns.ruleId()).isEqualTo("drift.high");
        assertThat(dns.attributes()).containsExactly("alias");

        var db = classify("aws_db_instance", "{\"allocated_storage\":20}", "{\"allocated_storage\":30}");
        assertThat(db.ruleId()).isEqualTo("drift.medium");

        var tags = classify("aws_security_group", "{\"tags\":{\"a\":\"1\"},\"tags_all\":{\"a\":\"1\"}}",
                "{\"tags\":{\"a\":\"2\"},\"tags_all\":{\"a\":\"2\"}}");
        assertThat(tags.ruleId()).as("태그만 바뀌면 낮음").isEqualTo("drift.low");
    }

    @Test
    void ignoresKnownNoise() {
        assertThat(classify("aws_db_instance", "{\"latest_restorable_time\":\"t1\"}", "{\"latest_restorable_time\":\"t2\"}")
                .ruleId()).isNull();
        assertThat(classify("aws_iam_role", "{\"inline_policy\":[],\"managed_policy_arns\":[]}",
                "{\"inline_policy\":[{\"name\":\"x\"}],\"managed_policy_arns\":[\"arn\"]}").ruleId()).isNull();
        assertThat(classify("aws_instance", "{\"ebs_block_device\":[]}", "{\"ebs_block_device\":[{\"device_name\":\"/dev/xvdaa\"}]}")
                .ruleId()).isNull();
        // 다른 종류의 같은 이름 속성은 노이즈가 아니다
        assertThat(classify("aws_launch_template", "{\"ebs_block_device\":[]}", "{\"ebs_block_device\":[{}]}").ruleId())
                .isEqualTo("drift.medium");
    }

    @Test
    void resourceDeletedOutsideTerraformIsADrift() {
        var drift = DriftClassifier.classify(MAPPER.readTree("""
                {"address":"aws_vpc_security_group_ingress_rule.x","type":"aws_vpc_security_group_ingress_rule",
                 "change":{"actions":["delete"],"before":{"cidr_ipv4":"0.0.0.0/0"},"after":null}}
                """));
        assertThat(drift.ruleId()).isEqualTo("drift.high");
        assertThat(drift.action()).isEqualTo("delete");
    }

    private static DriftClassifier.Drift classify(String type, String before, String after) {
        return DriftClassifier.classify(MAPPER.readTree("""
                {"address":"%s.x","type":"%s","change":{"actions":["update"],"before":%s,"after":%s}}
                """.formatted(type, type, before, after)));
    }
}
