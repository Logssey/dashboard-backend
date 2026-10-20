package com.logssey.iacworker.state;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.logssey.iacworker.graph.GraphEnricher;

import org.neo4j.driver.Driver;

/** 그래프에서 tfstate 버킷을 읽을 수 있는 주체 (Cartography 권한 매핑의 CAN_READ, 거부 반영). */
public class StateReaders {

    private final Driver driver;

    public StateReaders(Driver driver) {
        this.driver = driver;
    }

    public record Reader(String kind, String name) {
    }

    public record Bucket(String arn, String name, List<Reader> readers) {
    }

    public List<Bucket> tfstateReaders(List<String> tfstateArns) {
        try (var session = driver.session()) {
            return session.executeRead(tx -> {
                List<Bucket> buckets = new ArrayList<>();
                tx.run("""
                        UNWIND $arns AS arn
                        MATCH (b:AWSS3Bucket {arn: arn})
                        OPTIONAL MATCH (p)-[:CAN_READ]->(b)
                        WITH b, p ORDER BY %s
                        RETURN b.arn AS arn, b.name AS name,
                               collect(CASE WHEN p IS NULL THEN NULL ELSE {kind: %s, name: %s} END) AS readers
                        ORDER BY name
                        """.formatted(GraphEnricher.name("p"), GraphEnricher.kind("p"), GraphEnricher.name("p")),
                        Map.of("arns", tfstateArns, "kinds", List.of("AWSUser", "AWSRole", "AWSGroup")))
                        .forEachRemaining(r -> buckets.add(new Bucket(r.get("arn").asString(), r.get("name").asString(),
                                r.get("readers").asList(v -> new Reader(v.get("kind").asString(), v.get("name").asString())))));
                return buckets;
            });
        }
    }
}
