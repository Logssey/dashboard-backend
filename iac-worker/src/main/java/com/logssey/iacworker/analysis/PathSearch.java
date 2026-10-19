package com.logssey.iacworker.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import com.logssey.iacworker.graph.GraphEnricher;

/** GraphEnricher.openPaths() 와 같은 규칙으로 메모리 그래프에서 경로를 찾는다. */
final class PathSearch {

    static final String INTERNET = "internet";

    record FoundPath(List<GraphSnapshot.Node> nodes, List<GraphSnapshot.Edge> edges) {

        List<GraphEnricher.Hop> hops() {
            return nodes.stream().map(GraphSnapshot.Node::hop).toList();
        }

        GraphSnapshot.Node target() {
            return nodes.getLast();
        }

        String fingerprint() {
            return GraphEnricher.fingerprint(hops());
        }
    }

    private PathSearch() {
    }

    static Map<String, FoundPath> find(Map<String, GraphSnapshot.Node> nodes, List<GraphSnapshot.Edge> edges) {
        Map<String, List<GraphSnapshot.Edge>> outgoing = new HashMap<>();
        for (var edge : new LinkedHashSet<>(edges)) {
            outgoing.computeIfAbsent(edge.from(), k -> new ArrayList<>()).add(edge);
        }
        Map<String, FoundPath> found = new HashMap<>();
        var start = nodes.get(INTERNET);
        if (start != null) {
            walk(start, nodes, outgoing, new ArrayList<>(List.of(start)), new ArrayList<>(), found);
        }
        return found;
    }

    private static void walk(GraphSnapshot.Node at, Map<String, GraphSnapshot.Node> nodes,
                             Map<String, List<GraphSnapshot.Edge>> outgoing, List<GraphSnapshot.Node> path,
                             List<GraphSnapshot.Edge> edges, Map<String, FoundPath> found) {
        if (edges.size() == GraphEnricher.MAX_HOPS) return;
        for (var edge : outgoing.getOrDefault(at.id(), List.of())) {
            var next = nodes.get(edge.to());
            if (next == null || path.contains(next)) continue;
            path.add(next);
            edges.add(edge);
            if (next.tier() != null) {
                var p = new FoundPath(List.copyOf(path), List.copyOf(edges));
                found.putIfAbsent(p.fingerprint(), p);
            } else {
                walk(next, nodes, outgoing, path, edges, found);
            }
            path.removeLast();
            edges.removeLast();
        }
    }
}
