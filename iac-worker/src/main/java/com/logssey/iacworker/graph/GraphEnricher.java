package com.logssey.iacworker.graph;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.neo4j.driver.Driver;
import org.neo4j.driver.Value;

/**
 * Cartography 그래프에 경로 계산에 필요한 관계를 더하고(IaC 보안 database-schema "그래프 스키마"),
 * 인터넷에서 등급이 매겨진 데이터까지 가는 경로를 찾는다.
 *
 * 보강 관계는 _source = 'logssey' 와 이번 실행 태그를 달고, 이번에 다시 확인되지 않은 것은 지운다.
 * Cartography 가 만든 노드·관계는 바꾸지 않는다 (등급 표시 속성 logssey_tier 만 붙인다).
 */
public class GraphEnricher {

    /** 경로가 지나는 관계. 방향은 모두 "도달·획득" 방향이다. */
    static final String PATH_RELATIONSHIPS = "CAN_REACH|ORIGIN|EXPOSE|HAS_CREDS_OF|IS_INSTANCE|CAN_READ";
    static final int MAX_HOPS = 6;
    /** 노드 라벨 순서는 정해져 있지 않아, 경로 표시에 쓸 종류를 이 순서로 고른다. */
    static final List<String> HOP_KINDS = List.of("AWSCloudFrontDistribution", "AWSLoadBalancerV2",
            "AWSEC2Instance", "KubernetesNode", "KubernetesPod", "AWSRole", "AWSUser", "AWSGroup",
            "AWSSecretsManagerSecret", "AWSS3Bucket", "AWSRDSInstance");

    private final Driver driver;

    public GraphEnricher(Driver driver) {
        this.driver = driver;
    }

    public record DataAsset(long id, String arn, int tier) {
    }

    public record Hop(String kind, String id, String name) {
    }

    public record FoundPath(List<Hop> hops, long dataAssetId, int tier) {
    }

    public record Stats(long reach, long origin, long credentials, long instances, long tiered, long removed) {
    }

    public Stats enrich(long tag, List<DataAsset> assets, List<CloudFrontOrigins.Origin> origins,
                        Map<String, String> nodeAddresses) {
        try (var session = driver.session()) {
            return session.executeWrite(tx -> {
                tx.run("""
                        MERGE (i:LogsseyInternet {id: 'internet'})
                        SET i._source = 'logssey', i.lastupdated = $tag
                        """, Map.of("tag", tag));

                tx.run("MATCH (n) WHERE n.logssey_tier IS NOT NULL REMOVE n.logssey_tier, n.logssey_data_asset_id");
                long tiered = count(tx.run("""
                        UNWIND $assets AS a
                        MATCH (n) WHERE (n:AWSS3Bucket OR n:AWSSecretsManagerSecret OR n:AWSRDSInstance) AND n.arn = a.arn
                        SET n.logssey_tier = a.tier, n.logssey_data_asset_id = a.id
                        RETURN count(n) AS n
                        """, Map.of("assets", assets.stream()
                        .map(a -> Map.<String, Object>of("id", a.id(), "arn", a.arn(), "tier", a.tier())).toList())));

                // CloudFront 는 인터넷에 열려 있다
                long reach = count(tx.run("""
                        MATCH (i:LogsseyInternet {id: 'internet'}), (c:AWSCloudFrontDistribution)
                        WHERE c.enabled
                        MERGE (i)-[r:CAN_REACH]->(c)
                        SET r._source = 'logssey', r.lastupdated = $tag, r.port = 443
                        RETURN count(r) AS n
                        """, Map.of("tag", tag)));
                // 인터넷용 LB 는 보안 그룹이 리스너 포트를 0.0.0.0/0 에 열었을 때만 직접 도달한다
                reach += count(tx.run("""
                        MATCH (i:LogsseyInternet {id: 'internet'})
                        MATCH (lb:AWSLoadBalancerV2 {scheme: 'internet-facing'})-[:ELBV2_LISTENER]->(l:AWSELBV2Listener)
                        MATCH (lb)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(:AWSEC2SecurityGroup)
                              <-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:AWSIpPermissionInbound)
                              <-[:MEMBER_OF_IP_RULE]-(:AWSIpRange {id: '0.0.0.0/0'})
                        WHERE rule.protocol = '-1' OR (rule.fromport <= l.port AND l.port <= rule.toport)
                        WITH i, lb, min(l.port) AS port
                        MERGE (i)-[r:CAN_REACH]->(lb)
                        SET r._source = 'logssey', r.lastupdated = $tag, r.port = port
                        RETURN count(r) AS n
                        """, Map.of("tag", tag)));

                long origin = count(tx.run("""
                        UNWIND $origins AS o
                        MATCH (c:AWSCloudFrontDistribution {arn: o.arn})
                        MATCH (lb:AWSLoadBalancerV2)
                        WHERE toLower(lb.dnsname) = toLower(o.domain)
                           OR EXISTS { MATCH (d:AWSDNSRecord)-[:DNS_POINTS_TO]->(lb) WHERE toLower(d.name) = toLower(o.domain) }
                        MERGE (c)-[r:ORIGIN]->(lb)
                        SET r._source = 'logssey', r.lastupdated = $tag
                        RETURN count(r) AS n
                        """, Map.of("tag", tag, "origins", origins.stream()
                        .map(o -> Map.<String, Object>of("arn", o.distributionArn(), "domain", o.domainName())).toList())));

                // IMDSv1 이 열린 인스턴스에서는 웹 요청 위조(SSRF) 한 번으로 역할 자격 증명을 얻는다
                long credentials = count(tx.run("""
                        MATCH (e:AWSEC2Instance)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)-[:ASSOCIATED_WITH]->(role:AWSRole)
                        WHERE e.metadatahttptokens = 'optional' AND coalesce(e.metadatahttpendpoint, 'enabled') = 'enabled'
                        MERGE (e)-[r:HAS_CREDS_OF]->(role)
                        SET r._source = 'logssey', r.lastupdated = $tag, r.imds = 'v1'
                        RETURN count(r) AS n
                        """, Map.of("tag", tag)));

                long instances = count(tx.run("""
                        UNWIND $nodes AS k
                        MATCH (n:KubernetesNode {name: k.name})
                        MATCH (e:AWSEC2Instance {privateipaddress: k.ip})
                        MERGE (n)-[r:IS_INSTANCE]->(e)
                        SET r._source = 'logssey', r.lastupdated = $tag
                        RETURN count(r) AS n
                        """, Map.of("tag", tag, "nodes", nodeAddresses.entrySet().stream()
                        .map(e -> Map.<String, Object>of("name", e.getKey(), "ip", e.getValue())).toList())));

                long removed = count(tx.run("""
                        MATCH ()-[r]->() WHERE r._source = 'logssey' AND r.lastupdated <> $tag
                        DELETE r
                        RETURN count(*) AS n
                        """, Map.of("tag", tag)));
                return new Stats(reach, origin, credentials, instances, tiered, removed);
            });
        }
    }

    /** 인터넷에서 MAX_HOPS 이내로 등급 노드까지 가는 경로. 중간에 다른 등급 노드를 지나지 않는다. */
    public List<FoundPath> openPaths() {
        try (var session = driver.session()) {
            return session.executeRead(tx -> {
                var result = tx.run("""
                        MATCH p = (:LogsseyInternet {id: 'internet'})-[:%s*1..%d]->(t)
                        WHERE t.logssey_tier IS NOT NULL
                          AND none(n IN nodes(p)[1..-1] WHERE n.logssey_tier IS NOT NULL)
                          AND size(nodes(p)) = size(reduce(seen = [], n IN nodes(p) |
                                                    CASE WHEN n IN seen THEN seen ELSE seen + n END))
                        RETURN [n IN nodes(p) | {kind: CASE WHEN n:LogsseyInternet THEN 'Internet'
                                                     ELSE head([k IN $kinds WHERE k IN labels(n)] + labels(n)) END,
                                                 id: toString(coalesce(n.arn, n.id, n.name)),
                                                 name: toString(coalesce(n.name, n.db_instance_identifier, n.id))}] AS hops,
                               t.logssey_data_asset_id AS asset, t.logssey_tier AS tier
                        """.formatted(PATH_RELATIONSHIPS, MAX_HOPS), Map.of("kinds", HOP_KINDS));
                List<FoundPath> paths = new ArrayList<>();
                result.forEachRemaining(record -> paths.add(new FoundPath(
                        record.get("hops").asList(GraphEnricher::hop),
                        record.get("asset").asLong(), record.get("tier").asInt())));
                return paths;
            });
        }
    }

    private static Hop hop(Value value) {
        return new Hop(value.get("kind").asString(), value.get("id").asString(), value.get("name").asString());
    }

    private static long count(org.neo4j.driver.Result result) {
        return result.single().get("n").asLong();
    }
}
