package com.logssey.iacworker.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.logssey.iacworker.graph.GraphEnricher;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * ① 경로 분석 (FR-P2·P3). plan 의 변경을 그래프 사본에 반영해 머지 전·후 경로를 비교한다.
 *
 * 반영하는 변경 (MVP): 역할 인라인 정책(aws_iam_role_policy), 관리형 정책 연결(aws_iam_role_policy_attachment),
 * 인스턴스 IMDS(aws_instance.metadata_options.http_tokens). 보안 그룹은 백로그.
 * 바뀐 역할은 등급 데이터에 대한 읽기 권한을 전·후 모두 같은 평가기로 다시 계산해 비교한다.
 */
public class AnalysisEngine {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final IamSimulator simulator;

    public AnalysisEngine(IamSimulator simulator) {
        this.simulator = simulator;
    }

    public record Cause(String address, String action) {
    }

    public record Change(String change, String ruleId, int tier, String severity, String enforcement,
                         String fingerprint, List<GraphEnricher.Hop> hops, Cause cause, ObjectNode evidence,
                         String roleId) {
    }

    /** ③ State 영향. 읽기 주체가 늘면 state.reader_increase (경고·HIGH, rule-spec). */
    public record State(String ruleId, String severity, int readersBefore, int readersAfter, int secretsAdded) {
    }

    public record Result(List<Change> changes, State state, String verdict, String highestSeverity,
                         Map<String, Integer> resources) {
    }

    public Result analyze(GraphSnapshot graph, JsonNode plan, Set<String> tfstateArns) {
        var changes = PlanChanges.read(plan, graph);

        Map<String, Map<String, Policy>> beforePolicies = new HashMap<>();
        for (String roleId : changes.rolePolicies().keySet()) {
            beforePolicies.put(roleId, graph.roles().get(roleId).policies());
        }
        var before = edges(graph, changes, beforePolicies, false);
        var after = edges(graph, changes, changes.rolePolicies(), true);

        var beforePaths = PathSearch.find(graph.nodes(), before);
        var afterPaths = PathSearch.find(graph.nodes(), after);

        // 머지 전에 이미 닿던 데이터까지의 가장 짧은 길이
        Map<String, Integer> shortestBefore = new HashMap<>();
        beforePaths.values().forEach(p -> shortestBefore.merge(p.target().id(), p.edges().size(), Math::min));

        List<Change> result = new ArrayList<>();
        for (var entry : afterPaths.entrySet()) {
            if (beforePaths.containsKey(entry.getKey())) continue;
            var path = entry.getValue();
            int tier = path.target().tier();
            if (tier > 2) continue;
            var cause = cause(path, changes);
            String roleId = credentialRole(path);
            var evidence = MAPPER.createObjectNode();
            if (cause != null) evidence.put("causeAction", cause.action());
            Integer shortest = shortestBefore.get(path.target().id());
            if (shortest != null && path.edges().size() < shortest) {
                // 이미 닿던 데이터까지 더 짧은 길이 생김: 새 노출이 아니라 단축 (rule-spec path.shortened)
                result.add(new Change("SHORTENED", "path.shortened", tier, "MEDIUM", "WARN", entry.getKey(),
                        path.hops(), cause, evidence, roleId));
            } else if (tier == 1) {
                // 1등급 차단은 시뮬레이터가 허용을 확인했을 때만. 아니면 경고·HIGH 로 낮춘다 (rule-spec)
                String beforeDecision = decide(graph, beforePolicies, roleId, path.target());
                String afterDecision = decide(graph, changes.rolePolicies(), roleId, path.target());
                evidence.putObject("simulator").put("before", beforeDecision).put("after", afterDecision);
                boolean confirmed = "allowed".equals(afterDecision);
                result.add(new Change("ADDED", "path.tier1.added", 1, confirmed ? "CRITICAL" : "HIGH",
                        confirmed ? "BLOCK" : "WARN", entry.getKey(), path.hops(), cause, evidence, roleId));
            } else {
                result.add(new Change("ADDED", "path.tier2.added", 2, "HIGH", "WARN", entry.getKey(), path.hops(),
                        cause, evidence, roleId));
            }
        }
        for (var entry : beforePaths.entrySet()) {
            if (afterPaths.containsKey(entry.getKey())) continue;
            var path = entry.getValue();
            var cause = cause(path, changes);
            var evidence = MAPPER.createObjectNode();
            if (cause != null) evidence.put("causeAction", cause.action());
            result.add(new Change("REMOVED", "path.removed", path.target().tier(), null, "INFO", entry.getKey(),
                    path.hops(), cause, evidence, credentialRole(path)));
        }
        List<String> order = List.of("ADDED", "SHORTENED", "REMOVED");
        result.sort((a, b) -> a.change().equals(b.change())
                ? Integer.compare(a.tier(), b.tier()) : Integer.compare(order.indexOf(a.change()), order.indexOf(b.change())));

        int readersBefore = readers(graph, before, tfstateArns);
        int readersAfter = readers(graph, after, tfstateArns);
        boolean increased = readersAfter > readersBefore;
        var state = new State(increased ? "state.reader_increase" : null, increased ? "HIGH" : null,
                readersBefore, readersAfter, secretsAdded(plan));

        String verdict = verdict(result);
        if (increased && (verdict.equals("PASS") || verdict.equals("INFO"))) verdict = "WARN";
        String highest = highest(result);
        if (increased && (highest == null || !highest.equals("CRITICAL"))) highest = "HIGH";
        return new Result(result, state, verdict, highest, changes.resources());
    }

    /** tfstate 버킷을 읽을 수 있는 서로 다른 주체 수. */
    private static int readers(GraphSnapshot graph, List<GraphSnapshot.Edge> edges, Set<String> tfstateArns) {
        Set<String> readers = new java.util.HashSet<>();
        for (var edge : edges) {
            var target = graph.nodes().get(edge.to());
            if (edge.type().equals("CAN_READ") && target != null && tfstateArns.contains(target.arn())) {
                readers.add(edge.from());
            }
        }
        return readers.size();
    }

    /** State 에 새로 들어가는 민감값이 있는 리소스 수 (생성·변경 뒤 sensitive 표시가 생기는 것). */
    private static int secretsAdded(JsonNode plan) {
        int count = 0;
        for (JsonNode resource : plan.path("resource_changes")) {
            var change = resource.path("change");
            var actions = change.path("actions").toString();
            if (!actions.contains("create") && !actions.contains("update")) continue;
            if (hasTrue(change.path("after_sensitive")) && !hasTrue(change.path("before_sensitive"))) count++;
        }
        return count;
    }

    private static boolean hasTrue(JsonNode marker) {
        if (marker.isBoolean()) return marker.asBoolean();
        for (JsonNode child : marker) {
            if (hasTrue(child)) return true;
        }
        return false;
    }

    /** 경로 관계. 바뀐 인스턴스의 자격 증명과 바뀐 역할의 등급 데이터 읽기 권한만 다시 계산한다. */
    private static List<GraphSnapshot.Edge> edges(GraphSnapshot graph, PlanChanges changes,
                                                  Map<String, Map<String, Policy>> policies, boolean after) {
        Set<String> changedInstances = changes.httpTokens().keySet();
        Set<String> changedRoles = changes.rolePolicies().keySet();
        List<GraphSnapshot.Edge> edges = new ArrayList<>();
        for (var edge : graph.edges()) {
            if (edge.type().equals("HAS_CREDS_OF") && changedInstances.contains(edge.from())) continue;
            if (edge.type().equals("CAN_READ") && changedRoles.contains(edge.from())
                    && graph.nodes().get(edge.to()).tier() != null) continue;
            edges.add(edge);
        }
        for (String nodeId : changedInstances) {
            var instance = graph.instances().get(nodeId);
            String tokens = after ? changes.httpTokens().get(nodeId) : instance.httpTokens();
            if (instance.exposesCredentials(tokens)) {
                for (String roleId : instance.roleIds()) edges.add(new GraphSnapshot.Edge(nodeId, "HAS_CREDS_OF", roleId));
            }
        }
        for (String roleId : changedRoles) {
            var rolePolicies = policies.get(roleId).values();
            for (var target : graph.nodes().values()) {
                var request = ReadRequest.of(target);
                if (request != null && PolicyEvaluator.allows(rolePolicies, request.action(), request.resource())) {
                    edges.add(new GraphSnapshot.Edge(roleId, "CAN_READ", target.id()));
                }
            }
        }
        return edges;
    }

    private String decide(GraphSnapshot graph, Map<String, Map<String, Policy>> changed, String roleId,
                          GraphSnapshot.Node target) {
        var request = ReadRequest.of(target);
        if (roleId == null || request == null || !graph.roles().containsKey(roleId)) return "implicitDeny";
        Collection<Policy> policies = changed.containsKey(roleId) ? changed.get(roleId).values()
                : graph.roles().get(roleId).policies().values();
        return simulator.decide(documents(policies, request.action()), request.action(), request.resource());
    }

    /**
     * 시뮬레이터에 넘길 정책 문서. 해당 서비스에 걸릴 수 있는 문장만 정책별 문서로 묶는다.
     * 조건은 넣지 않는다 (조건부 거부는 무조건 거부, ADR-04 와 같은 규칙).
     */
    static List<String> documents(Collection<Policy> policies, String action) {
        String service = action.substring(0, action.indexOf(':') + 1).toLowerCase();
        List<String> documents = new ArrayList<>();
        for (Policy policy : policies) {
            ArrayNode statements = MAPPER.createArrayNode();
            for (PolicyStatement s : policy.statements()) {
                boolean relevant = !s.notActions().isEmpty() || s.actions().stream()
                        .anyMatch(a -> a.equals("*") || a.toLowerCase().startsWith(service));
                if (!relevant) continue;
                ObjectNode statement = statements.addObject().put("Effect", s.effect());
                if (!s.notActions().isEmpty()) statement.putPOJO("NotAction", s.notActions());
                else statement.putPOJO("Action", s.actions());
                if (!s.notResources().isEmpty()) statement.putPOJO("NotResource", s.notResources());
                else statement.putPOJO("Resource", s.resources().isEmpty() ? List.of("*") : s.resources());
            }
            if (!statements.isEmpty()) {
                documents.add(MAPPER.writeValueAsString(MAPPER.createObjectNode().put("Version", "2012-10-17")
                        .set("Statement", statements)));
            }
        }
        return documents;
    }

    /** 경로를 만들거나 끊은 plan 변경. 경로의 관계를 앞에서부터 보며 처음 걸리는 것. */
    private static Cause cause(PathSearch.FoundPath path, PlanChanges changes) {
        for (var edge : path.edges()) {
            if (edge.type().equals("HAS_CREDS_OF") && changes.instanceCauses().containsKey(edge.from())) {
                return changes.instanceCauses().get(edge.from());
            }
            if (edge.type().equals("CAN_READ") && changes.roleCauses().containsKey(edge.from())) {
                return changes.roleCauses().get(edge.from());
            }
        }
        return null;
    }

    private static String credentialRole(PathSearch.FoundPath path) {
        for (var edge : path.edges()) {
            if (edge.type().equals("HAS_CREDS_OF")) return edge.to();
        }
        return null;
    }

    private static String verdict(List<Change> changes) {
        if (changes.stream().anyMatch(c -> "BLOCK".equals(c.enforcement()))) return "BLOCK";
        if (changes.stream().anyMatch(c -> "WARN".equals(c.enforcement()))) return "WARN";
        if (!changes.isEmpty()) return "INFO";
        return "PASS";
    }

    private static String highest(List<Change> changes) {
        for (String severity : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW")) {
            if (changes.stream().anyMatch(c -> severity.equals(c.severity()))) return severity;
        }
        return null;
    }

    /** 등급 데이터를 "읽는다" 는 것을 무엇으로 볼지. RDS 는 네트워크 경로라 여기서는 다루지 않는다. */
    record ReadRequest(String action, String resource) {

        static ReadRequest of(GraphSnapshot.Node node) {
            if (node.tier() == null || node.arn() == null) return null;
            return switch (node.kind()) {
                case "AWSS3Bucket" -> new ReadRequest("s3:GetObject", node.arn() + "/*");
                case "AWSSecretsManagerSecret" -> new ReadRequest("secretsmanager:GetSecretValue", node.arn());
                default -> null;
            };
        }
    }

    /** plan 에서 읽은, 그래프에 반영할 변경. */
    record PlanChanges(Map<String, Map<String, Policy>> rolePolicies, Map<String, Cause> roleCauses,
                       Map<String, String> httpTokens, Map<String, Cause> instanceCauses,
                       Map<String, Integer> resources) {

        static PlanChanges read(JsonNode plan, GraphSnapshot graph) {
            Map<String, String> roleIdByName = new HashMap<>();
            graph.roles().values().forEach(r -> roleIdByName.put(r.name(), r.id()));
            Map<String, String> nodeByInstanceId = new HashMap<>();
            graph.instances().values().forEach(i -> nodeByInstanceId.put(i.instanceId(), i.nodeId()));

            Map<String, Map<String, Policy>> rolePolicies = new LinkedHashMap<>();
            Map<String, Cause> roleCauses = new LinkedHashMap<>();
            Map<String, String> httpTokens = new LinkedHashMap<>();
            Map<String, Cause> instanceCauses = new LinkedHashMap<>();
            int add = 0;
            int change = 0;
            int delete = 0;

            for (JsonNode resource : plan.path("resource_changes")) {
                var actions = new LinkedHashSet<String>();
                resource.path("change").path("actions").forEach(a -> actions.add(a.asString()));
                if (actions.equals(Set.of("no-op")) || actions.equals(Set.of("read"))) continue;
                if (actions.contains("create")) add++;
                if (actions.equals(Set.of("update"))) change++;
                if (actions.contains("delete")) delete++;
                String action = actions.contains("delete") && actions.contains("create") ? "REPLACE"
                        : actions.iterator().next().toUpperCase();
                var cause = new Cause(resource.path("address").asString(), action);
                JsonNode before = resource.path("change").path("before");
                JsonNode after = resource.path("change").path("after");

                switch (resource.path("type").asString()) {
                    case "aws_iam_role_policy" -> {
                        String roleId = roleIdByName.get(text(after, "role", text(before, "role", null)));
                        if (roleId == null) continue;
                        var policies = rolePolicies.computeIfAbsent(roleId,
                                id -> new LinkedHashMap<>(graph.roles().get(id).policies()));
                        if (before.isObject()) policies.remove(Policy.inlineKey(text(before, "name", "")));
                        if (after.isObject()) {
                            String name = text(after, "name", "");
                            policies.put(Policy.inlineKey(name), new Policy(Policy.inlineKey(name), roleId + "/inline_policy/" + name,
                                    statements(text(after, "policy", null))));
                        }
                        roleCauses.putIfAbsent(roleId, cause);
                    }
                    case "aws_iam_role_policy_attachment" -> {
                        String roleId = roleIdByName.get(text(after, "role", text(before, "role", null)));
                        if (roleId == null) continue;
                        var policies = rolePolicies.computeIfAbsent(roleId,
                                id -> new LinkedHashMap<>(graph.roles().get(id).policies()));
                        if (before.isObject()) policies.remove(Policy.managedKey(text(before, "policy_arn", "")));
                        if (after.isObject()) {
                            String arn = text(after, "policy_arn", "");
                            // 그래프에 없는 관리형 정책은 문장을 모른다: 허용이 없는 것으로 본다
                            policies.put(Policy.managedKey(arn), Objects.requireNonNullElse(graph.managed().get(arn),
                                    new Policy(Policy.managedKey(arn), arn, List.of())));
                        }
                        roleCauses.putIfAbsent(roleId, cause);
                    }
                    case "aws_instance" -> {
                        String nodeId = nodeByInstanceId.get(text(before, "id", null));
                        String tokens = text(after.path("metadata_options").path(0), "http_tokens", null);
                        if (nodeId == null || tokens == null) continue;
                        if (!tokens.equals(graph.instances().get(nodeId).httpTokens())) {
                            httpTokens.put(nodeId, tokens);
                            instanceCauses.put(nodeId, cause);
                        }
                    }
                    default -> { }
                }
            }
            return new PlanChanges(rolePolicies, roleCauses, httpTokens, instanceCauses,
                    Map.of("add", add, "change", change, "delete", delete));
        }

        private static List<PolicyStatement> statements(String document) {
            if (document == null || document.isBlank() || document.equals("(sensitive)")) return List.of();
            List<PolicyStatement> statements = new ArrayList<>();
            JsonNode root = MAPPER.readTree(document).path("Statement");
            for (JsonNode s : root.isArray() ? root : MAPPER.createArrayNode().add(root)) {
                statements.add(new PolicyStatement(s.path("Effect").asString(), list(s.path("Action")),
                        list(s.path("NotAction")), list(s.path("Resource")), list(s.path("NotResource")),
                        s.has("Condition") ? s.get("Condition").toString() : null));
            }
            return statements;
        }

        private static List<String> list(JsonNode node) {
            if (node.isMissingNode() || node.isNull()) return List.of();
            if (node.isArray()) {
                List<String> values = new ArrayList<>();
                node.forEach(v -> values.add(v.asString()));
                return values;
            }
            return List.of(node.asString());
        }

        private static String text(JsonNode node, String field, String fallback) {
            JsonNode value = node.path(field);
            return value.isString() ? value.asString() : fallback;
        }
    }
}
