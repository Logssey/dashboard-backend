package com.logssey.reach.rule;

import static com.logssey.reach.rule.ReachVulnFunctionData.require;
import static com.logssey.reach.rule.ReachVulnFunctionData.text;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import com.logssey.reach.rule.dto.ReachRuleResponse;
import com.logssey.reach.rule.dto.ReachVulnFunctionResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * 판정 규칙 데이터 (API-09, 명세 3-7). 분석기가 만든 data/rules.json을 그대로 넣어 두고 기동 때 한 번 읽는다.
 * 패키지와 취약 함수 id는 취약 함수 데이터(API-10)에서 같은 CVE로 찾는다.
 * 조건에 정의되지 않은 사실이 나오거나 형식이 다르면 기동을 멈춘다
 */
@Component
public class ReachRuleData {

    static final String RESOURCE = "reach/rules.json";
    static final String SCHEMA_PREFIX = "reach-rules/";
    /** 명세 3-7: 항상 이 순서로 본다 (reachable_if → unreachable_if → unknown_if → otherwise) */
    static final List<String> EVALUATION_ORDER = List.of("REACHABLE", "UNREACHABLE", "UNKNOWN", "DEFAULT");
    /** 호출 그래프가 만드는 가짜 사실. 앱 코드에서 찾는 사실이 아니라 facts에서 뺀다 (rules.json note) */
    static final Set<String> CALLGRAPH_FACTS = Set.of("sink", "sink_weak", "sinks_missing", "package");
    private static final List<String> CONDITIONS = List.of("reachable_if", "unreachable_if", "unknown_if");
    /** 명세 0절 식별자 규약: 사실은 F-<사실 이름>. Finding 근거의 factId(API-05)와 같은 값이 되게 응답에서 붙인다 */
    static final String FACT_PREFIX = "F-";
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final String version;
    private final List<ReachRuleResponse> rules;

    @Autowired   // 생성자가 둘이라 Spring이 쓸 쪽을 표시한다
    public ReachRuleData(ReachVulnFunctionData vulnFunctions) {
        this(ReachVulnFunctionData.read(RESOURCE), vulnFunctions);
    }

    ReachRuleData(JsonNode root, ReachVulnFunctionData vulnFunctions) {
        String schema = text(root, "schema");
        require(schema.startsWith(SCHEMA_PREFIX), "Unsupported rules schema: " + schema);
        this.version = schema.substring(SCHEMA_PREFIX.length());

        var definitions = new HashMap<String, JsonNode>();
        for (String list : List.of("facts", "repo_facts")) {
            for (JsonNode fact : root.path(list)) {
                String id = text(fact, "id");
                require(definitions.put(id, fact) == null, "Duplicate fact: " + id);
            }
        }

        var parsed = new ArrayList<ReachRuleResponse>();
        JsonNode verdicts = root.path("verdicts");
        require(verdicts.isObject() && !verdicts.isEmpty(), "rules must contain verdicts");
        for (var entry : verdicts.properties()) {
            String cve = entry.getKey();
            JsonNode verdict = entry.getValue();
            require(ReachVulnFunctionData.CVE.matcher(cve).matches(), "Invalid CVE id: " + cve);
            String method = text(verdict, "method").toUpperCase(Locale.ROOT);
            require(method.equals("RULE") || method.equals("CALLGRAPH"), "Unknown method for " + cve + ": " + method);
            String otherwise = text(verdict, "otherwise").toUpperCase(Locale.ROOT);
            require(EVALUATION_ORDER.contains(otherwise) && !otherwise.equals("DEFAULT"), "Unknown otherwise for " + cve);

            var facts = new LinkedHashSet<String>();
            for (String condition : CONDITIONS) {
                for (JsonNode all : verdict.path(condition)) {
                    for (JsonNode fact : all) {
                        String id = fact.asString().startsWith("!") ? fact.asString().substring(1) : fact.asString();
                        if (CALLGRAPH_FACTS.contains(id)) continue;
                        require(definitions.containsKey(id), "Undefined fact in " + cve + ": " + id);
                        facts.add(id);
                    }
                }
            }
            var info = new ArrayList<String>();
            for (JsonNode fact : verdict.path("info")) {
                require(definitions.containsKey(fact.asString()), "Undefined info fact in " + cve + ": " + fact.asString());
                info.add(fact.asString());
            }
            var reasons = new LinkedHashMap<String, String>();
            for (String status : List.of("REACHABLE", "UNREACHABLE", "UNKNOWN")) {
                JsonNode why = verdict.path("why_ko").path(status.toLowerCase(Locale.ROOT));
                if (why.isString()) reasons.put(status, why.asString());
            }
            List<Integer> functionIds = vulnFunctions.items().stream()
                    .filter(item -> item.cve().equals(cve)).map(ReachVulnFunctionResponse::id).toList();

            ObjectNode definition = MAPPER.createObjectNode();
            definition.set("verdict", verdict);
            ArrayNode used = definition.putArray("facts");
            var shown = new LinkedHashSet<>(facts);
            shown.addAll(info);
            shown.forEach(id -> used.add(definitions.get(id)));

            parsed.add(new ReachRuleResponse("RULE-" + cve, cve, method, vulnFunctions.packages(cve), prefixed(facts),
                    prefixed(info), EVALUATION_ORDER, otherwise, Collections.unmodifiableMap(reasons),
                    functionIds, definition, version));
        }
        this.rules = List.copyOf(parsed);
    }

    private static List<String> prefixed(java.util.Collection<String> ids) {
        return ids.stream().map(id -> FACT_PREFIX + id).toList();
    }

    /** 규칙 데이터 버전 (스키마 reach-rules/v0의 v0) */
    public String version() {
        return version;
    }

    /** definition까지 든 규칙 전부. 응답에 definition을 줄지는 Service가 정한다 */
    public List<ReachRuleResponse> rules() {
        return rules;
    }

    public Optional<ReachRuleResponse> rule(String ruleId) {
        return rules.stream().filter(rule -> rule.id().equals(ruleId)).findFirst();
    }
}
