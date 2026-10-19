package com.logssey.iacworker.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logssey.iacworker.graph.GraphEnricher;

import org.neo4j.driver.Driver;
import org.neo4j.driver.Record;
import org.neo4j.driver.Value;

import static com.logssey.iacworker.graph.GraphEnricher.id;
import static com.logssey.iacworker.graph.GraphEnricher.kind;
import static com.logssey.iacworker.graph.GraphEnricher.name;

/** 보강이 끝난 그래프에서 경로 관계, 인스턴스 IMDS, 역할 정책을 읽어 온다 (읽기 전용). */
public class GraphLoader {

    private static final String NODE = "{id: %s, kind: %s, name: %s, arn: %s.arn, tier: %s.logssey_tier, asset: %s.logssey_data_asset_id}";

    private final Driver driver;

    public GraphLoader(Driver driver) {
        this.driver = driver;
    }

    public GraphSnapshot load() {
        try (var session = driver.session()) {
            return session.executeRead(tx -> {
                Map<String, Object> kinds = Map.of("kinds", GraphEnricher.HOP_KINDS);
                Map<String, GraphSnapshot.Node> nodes = new HashMap<>();
                List<GraphSnapshot.Edge> edges = new ArrayList<>();
                tx.run("MATCH (a)-[r:" + GraphEnricher.PATH_RELATIONSHIPS + "]->(b) RETURN "
                        + node("a") + " AS a, type(r) AS type, " + node("b") + " AS b", kinds).forEachRemaining(r -> {
                    var a = node(r.get("a"));
                    var b = node(r.get("b"));
                    nodes.putIfAbsent(a.id(), a);
                    nodes.putIfAbsent(b.id(), b);
                    edges.add(new GraphSnapshot.Edge(a.id(), r.get("type").asString(), b.id()));
                });
                // 경로 관계가 아직 없는 등급 노드도 plan 반영 뒤 대상이 될 수 있다
                tx.run("MATCH (n) WHERE n.logssey_tier IS NOT NULL RETURN " + node("n") + " AS n", kinds)
                        .forEachRemaining(r -> nodes.putIfAbsent(node(r.get("n")).id(), node(r.get("n"))));

                Map<String, GraphSnapshot.Instance> instances = new HashMap<>();
                tx.run("""
                        MATCH (e:AWSEC2Instance)
                        OPTIONAL MATCH (e)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)-[:ASSOCIATED_WITH]->(role:AWSRole)
                        RETURN %s AS e, e.instanceid AS instanceId, e.metadatahttptokens AS tokens,
                               e.metadatahttpendpoint AS endpoint, collect(%s) AS roles,
                               collect(CASE WHEN role IS NULL THEN NULL ELSE %s END) AS roleNodes
                        """.formatted(node("e"), id("role"), node("role")), kinds).forEachRemaining(r -> {
                    var e = node(r.get("e"));
                    nodes.putIfAbsent(e.id(), e);
                    for (Value role : r.get("roleNodes").values()) nodes.putIfAbsent(node(role).id(), node(role));
                    instances.put(e.id(), new GraphSnapshot.Instance(e.id(), text(r, "instanceId"), text(r, "tokens"),
                            text(r, "endpoint"), r.get("roles").asList(Value::asString)));
                });

                Map<String, GraphSnapshot.Role> roles = new HashMap<>();
                tx.run("""
                        MATCH (role:AWSRole)
                        OPTIONAL MATCH (role)-[:POLICY]->(p:AWSPolicy)
                        OPTIONAL MATCH (p)-[:STATEMENT]->(s:AWSPolicyStatement)
                        WITH role, p, collect(s {.effect, .action, .notaction, .resource, .notresource, .condition}) AS statements
                        RETURN %s AS role, role.name AS name,
                               collect(CASE WHEN p IS NULL THEN NULL ELSE
                                   {id: p.id, name: p.name, type: p.type, statements: statements} END) AS policies
                        """.formatted(id("role")), Map.of()).forEachRemaining(r -> {
                    Map<String, Policy> policies = new LinkedHashMap<>();
                    for (Value p : r.get("policies").values()) {
                        var policy = policy(p);
                        policies.put(policy.key(), policy);
                    }
                    roles.put(r.get("role").asString(), new GraphSnapshot.Role(r.get("role").asString(),
                            text(r, "name"), policies));
                });

                Map<String, Policy> managed = new HashMap<>();
                tx.run("""
                        MATCH (p:AWSManagedPolicy)
                        OPTIONAL MATCH (p)-[:STATEMENT]->(s:AWSPolicyStatement)
                        WITH p, collect(s {.effect, .action, .notaction, .resource, .notresource, .condition}) AS statements
                        RETURN {id: p.id, name: p.name, type: 'managed', statements: statements} AS p
                        """).forEachRemaining(r -> {
                    var policy = policy(r.get("p"));
                    managed.put(policy.id(), policy);
                });
                return new GraphSnapshot(nodes, edges, instances, roles, managed);
            });
        }
    }

    private static String node(String n) {
        return NODE.formatted(id(n), kind(n), name(n), n, n, n);
    }

    private static GraphSnapshot.Node node(Value v) {
        return new GraphSnapshot.Node(v.get("id").asString(), v.get("kind").asString(), v.get("name").asString(),
                v.get("arn").isNull() ? null : v.get("arn").asString(),
                v.get("tier").isNull() ? null : v.get("tier").asInt(),
                v.get("asset").isNull() ? null : v.get("asset").asLong());
    }

    private static Policy policy(Value p) {
        List<PolicyStatement> statements = new ArrayList<>();
        for (Value s : p.get("statements").values()) {
            statements.add(new PolicyStatement(s.get("effect").asString(null), strings(s.get("action")),
                    strings(s.get("notaction")), strings(s.get("resource")), strings(s.get("notresource")),
                    s.get("condition").isNull() ? null : s.get("condition").toString()));
        }
        String id = p.get("id").asString();
        String key = "inline".equals(p.get("type").asString(null)) ? Policy.inlineKey(p.get("name").asString())
                : Policy.managedKey(id);
        return new Policy(key, id, statements);
    }

    private static List<String> strings(Value v) {
        if (v.isNull()) return List.of();
        return v.hasType(org.neo4j.driver.types.TypeSystem.getDefault().LIST()) ? v.asList(Value::asString)
                : List.of(v.asString());
    }

    private static String text(Record r, String key) {
        return r.get(key).isNull() ? null : r.get(key).asString();
    }
}
