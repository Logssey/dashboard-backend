package com.logssey.reach.rule;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.logssey.reach.rule.dto.ReachVulnFunctionResponse;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * 취약 함수 데이터 (API-10, 명세 3-8). 분석기가 만든 data/vuln-functions.json을 그대로 넣어 두고 기동 때 한 번 읽는다.
 * 파일이 깨졌거나 형식이 다르면 기동을 멈춘다(틀린 데이터를 보이느니 안 뜨는 게 낫다). 런타임 규칙 묶음(RuntimeRulePack)과 같은 방식이다.
 * CVE를 더할 때 코드를 고치지 않고 파일만 바꾼다(NFR-07). DB와 CI 업로드는 분석기가 CI에서 돌게 되면(인프라 단계) 붙인다
 */
@Component
public class ReachVulnFunctionData {

    static final String RESOURCE = "reach/vuln-functions.json";
    static final String SCHEMA_PREFIX = "reach-spec/";
    static final Pattern CVE = Pattern.compile("^CVE-(\\d{4})-(\\d{4,})$");
    private static final Pattern COMMIT = Pattern.compile("^https://github\\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})$");
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final String version;
    private final String generated;
    private final List<ReachVulnFunctionResponse> items;
    private final Map<String, List<String>> packagesByCve;

    public ReachVulnFunctionData() {
        this(read(RESOURCE));
    }

    ReachVulnFunctionData(JsonNode root) {
        String schema = text(root, "schema");
        require(schema.startsWith(SCHEMA_PREFIX), "Unsupported vuln-functions schema: " + schema);
        this.version = schema.substring(SCHEMA_PREFIX.length());
        this.generated = root.path("generated").isString() ? root.path("generated").asString() : null;

        var parsed = new ArrayList<ReachVulnFunctionResponse>();
        var packages = new LinkedHashMap<String, List<String>>();
        JsonNode cves = root.path("cves");
        require(cves.isArray() && !cves.isEmpty(), "vuln-functions must contain cves");
        for (JsonNode entry : cves) {
            String cve = text(entry, "cve");
            require(CVE.matcher(cve).matches(), "Invalid CVE id: " + cve);
            require(!packages.containsKey(cve), "Duplicate CVE: " + cve);
            String purl = purl(text(entry.path("package"), "coordinates"));
            packages.put(cve, List.of(purl));
            List<String> fixed = new ArrayList<>();
            entry.path("package").path("fixed").forEach(value -> fixed.add(value.asString()));
            fixed.sort(ReachVulnFunctionData::compareVersions);
            List<String> commits = new ArrayList<>();
            for (JsonNode source : entry.path("sources")) {
                var match = COMMIT.matcher(source.asString());
                if (match.matches()) commits.add(match.group(1) + "@" + match.group(2).substring(0, 8));
            }
            JsonNode sinks = entry.path("sinks");
            require(sinks.isArray() && !sinks.isEmpty(), "CVE without sinks: " + cve);
            for (JsonNode sink : sinks) {
                // id는 파일 순서다. 같은 데이터 버전 안에서만 같은 함수를 가리킨다
                parsed.add(new ReachVulnFunctionResponse(parsed.size() + 1, cve, purl, text(sink, "class"),
                        text(sink, "method"), optional(sink, "desc"), List.copyOf(fixed), List.copyOf(commits),
                        optional(sink, "confidence"), optional(sink, "note")));
            }
        }
        this.items = List.copyOf(parsed);
        this.packagesByCve = Map.copyOf(packages);
    }

    /** 데이터 버전 (스키마 reach-spec/v0의 v0) */
    public String version() {
        return version;
    }

    /** 생성 날짜 (파일의 generated, 예 2026-10-10). 없으면 null */
    public String generated() {
        return generated;
    }

    public List<ReachVulnFunctionResponse> items() {
        return items;
    }

    /** CVE의 패키지 purl(버전 제외). 규칙(API-09)이 쓴다 */
    public List<String> packages(String cve) {
        return packagesByCve.getOrDefault(cve, List.of());
    }

    /** CVE를 연도·번호 숫자로 비교한다 (CVE-2026-8763 < CVE-2026-13506) */
    static int compareCve(String a, String b) {
        var left = CVE.matcher(a);
        var right = CVE.matcher(b);
        if (!left.matches() || !right.matches()) return a.compareTo(b);
        int year = Integer.compare(Integer.parseInt(left.group(1)), Integer.parseInt(right.group(1)));
        return year != 0 ? year : Long.compare(Long.parseLong(left.group(2)), Long.parseLong(right.group(2)));
    }

    /** 숫자 칸은 숫자로, 나머지는 글자로 비교한다 (9.0.121 < 10.1.59 < 11.0.25) */
    static int compareVersions(String a, String b) {
        String[] left = a.split("[.\\-+_]");
        String[] right = b.split("[.\\-+_]");
        for (int i = 0; i < Math.max(left.length, right.length); i++) {
            String x = i < left.length ? left[i] : "";
            String y = i < right.length ? right[i] : "";
            int c = x.matches("\\d+") && y.matches("\\d+") ? Long.compare(Long.parseLong(x), Long.parseLong(y)) : x.compareTo(y);
            if (c != 0) return c;
        }
        return 0;
    }

    /** Maven 좌표 group:artifact → pkg:maven/group/artifact (명세 3-8 package는 버전 없는 purl) */
    static String purl(String coordinates) {
        String[] parts = coordinates.split(":");
        require(parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank(), "Invalid coordinates: " + coordinates);
        return "pkg:maven/" + parts[0] + "/" + parts[1];
    }

    static JsonNode read(String resource) {
        try (InputStream input = new ClassPathResource(resource).getInputStream()) {
            return MAPPER.readTree(input);
        } catch (IOException e) {
            throw new IllegalStateException("Reach data could not be loaded: " + resource, e);
        }
    }

    static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        require(value.isString() && !value.asString().isBlank(), "Missing field: " + field);
        return value.asString();
    }

    private static String optional(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isString() && !value.asString().isBlank() ? value.asString() : null;
    }

    static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
