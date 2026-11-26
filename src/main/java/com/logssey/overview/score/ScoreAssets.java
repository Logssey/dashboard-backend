package com.logssey.overview.score;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Set;

import tools.jackson.databind.json.JsonMapper;

/**
 * 보안 점수의 자산 목록 (ADR-D012 결정 2). 원천은 classpath의 overview/score-assets.json 하나다.
 * 데이터 자산(dataAssetKind)은 iac_data_assets의 같은 kind ARN을 모두 가진다. 묶어 센다(시크릿 9개 = 자산 하나)
 */
public record ScoreAssets(String version, String note, List<Asset> assets) {

    public static final Set<String> AREAS = Set.of("DATA", "CREDENTIAL", "DEPLOY", "WORKLOAD");
    public static final String RESOURCE = "overview/score-assets.json";

    /**
     * sources: 이 자산을 평가하는 기능(OverviewPart 이름). apps·repoPaths·arns·dataAssetKind는 결과를 이 자산에 잇는 단서다.
     * repoPaths의 repository "*"는 모든 레포다. 가중치는 등급에서 나온다(1등급 3, 2등급 2, 3등급 1)
     */
    public record Asset(String id, String name, int tier, String area, String dataAssetKind, List<String> arns,
                        List<String> apps, List<RepoPath> repoPaths, List<String> sources) {
        public Asset {
            arns = arns == null ? List.of() : List.copyOf(arns);
            apps = apps == null ? List.of() : List.copyOf(apps);
            repoPaths = repoPaths == null ? List.of() : List.copyOf(repoPaths);
            sources = sources == null ? List.of() : List.copyOf(sources);
            if (id == null || id.isBlank() || name == null || tier < 1 || tier > 3 || !AREAS.contains(area)) {
                throw new IllegalStateException(RESOURCE + ": bad asset " + id);
            }
        }

        public int weight() {
            return 4 - tier;
        }
    }

    public record RepoPath(String repository, String pathPrefix) {
        public RepoPath {
            pathPrefix = pathPrefix == null ? "" : pathPrefix;
        }
    }

    public static ScoreAssets load() {
        try (InputStream in = ScoreAssets.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException(RESOURCE + " is missing");
            var loaded = JsonMapper.builder().build().readValue(in, ScoreAssets.class);
            if (loaded.assets() == null || loaded.assets().isEmpty()) throw new IllegalStateException(RESOURCE + ": no assets");
            long distinct = loaded.assets().stream().map(Asset::id).distinct().count();
            if (distinct != loaded.assets().size()) throw new IllegalStateException(RESOURCE + ": duplicate asset id");
            return loaded;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
