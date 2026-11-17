package com.logssey.reach;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * 감시 대상 서비스 설정 (PRD FR-15 MVP: 설정 파일로 등록).
 * 서비스 이름을 코드에 두지 않고 설치마다 정한다. 운영은 /run/config/application.properties, 로컬은 reach/local-targets.properties.
 * 설정이 없으면 비어 있는 채로 뜬다: 대상을 정할 수 없어 CI 등록은 422, L1은 꺼진다(업로드 400, 목록은 빈 결과).
 * 값이 잘못됐으면(코드 형식, 중복) 기동을 멈춘다
 */
@ConfigurationProperties("logssey.reach")
public record ReachProperties(List<App> apps, L1 l1) {

    /** 앱의 생태계(purl type). Reach 스캔(분석기·CI 스크립트)은 maven만 한다. npm은 등록만(PRD 확장 단계, NFR-07) */
    public static final String MAVEN = "maven";
    private static final List<String> ECOSYSTEMS = List.of(MAVEN, "npm");

    /** reach_targets.app 칸 (V47 ck_reach_targets_app) */
    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,9}$");

    public ReachProperties {
        apps = apps == null ? List.of() : List.copyOf(apps);
        l1 = l1 == null ? new L1(null, null) : l1;
        var codes = new HashSet<String>();
        var repos = new HashSet<String>();
        var images = new HashSet<String>();
        for (var app : apps) {
            if (app == null || app.code() == null || !CODE.matcher(app.code()).matches()) {
                throw new IllegalStateException("logssey.reach.apps: code must match " + CODE.pattern());
            }
            if (!codes.add(app.code())) {
                throw new IllegalStateException("logssey.reach.apps: duplicate code " + app.code());
            }
            if (app.repo() == null && app.image() == null) {
                throw new IllegalStateException("logssey.reach.apps: " + app.code() + " needs repo or image");
            }
            if (app.repo() != null && !repos.add(repoName(app.repo()) + "\n" + (app.path() == null ? "" : app.path()))) {
                throw new IllegalStateException("logssey.reach.apps: duplicate repo/path for " + app.code());
            }
            if (app.image() != null && !images.add(app.image())) {
                throw new IllegalStateException("logssey.reach.apps: duplicate image for " + app.code());
            }
            if (!ECOSYSTEMS.contains(app.ecosystem())) {
                throw new IllegalStateException("logssey.reach.apps: " + app.code() + " ecosystem must be one of " + ECOSYSTEMS);
            }
        }
    }

    /**
     * 서비스 안의 앱 하나. repo는 레포 이름(소유자를 붙여도 이름만 본다), path는 레포 안 하위 경로(없으면 레포 전체),
     * image는 이미지 저장소(태그·digest 없이). repo와 image 중 하나는 있어야 한다.
     * ecosystem은 maven(기본) 또는 npm. 대시보드 스캔 요청(API-01)은 maven 앱만 받는다
     */
    public record App(String code, String repo, String path, String image, String ecosystem) {

        @ConstructorBinding   // 생성자가 둘이라 설정 값을 넣을 쪽을 표시한다
        public App {
            ecosystem = ecosystem == null || ecosystem.isBlank() ? MAVEN : ecosystem.trim().toLowerCase(Locale.ROOT);
        }

        /** ecosystem 없이(maven) */
        public App(String code, String repo, String path, String image) {
            this(code, repo, path, image, null);
        }

        /** Reach가 스캔할 수 있는 앱인가 (분석기·CI 스크립트는 Java/Gradle만) */
        public boolean scannable() {
            return MAVEN.equals(ecosystem);
        }
    }

    /** L1 수집 범위. cluster가 없거나 namespaces가 비면 L1이 꺼진다 */
    public record L1(String cluster, List<String> namespaces) {
        public L1 {
            namespaces = namespaces == null ? List.of() : List.copyOf(namespaces);
        }

        public boolean enabled() {
            return cluster != null && !cluster.isBlank() && !namespaces.isEmpty();
        }
    }

    /** 앱 코드. 설정 순서 그대로 (화면 선택지 순서) */
    public List<String> codes() {
        return apps.stream().map(App::code).toList();
    }

    /** 레포(+하위 경로)의 앱. 경로가 같은 것이 없으면 경로 없이 등록한 같은 레포의 앱(레포 전체) */
    public Optional<String> appOfRepo(String repo, String path) {
        String name = repoName(repo);
        return apps.stream()
                .filter(app -> app.repo() != null && repoName(app.repo()).equals(name)
                        && Objects.equals(app.path(), path))
                .findFirst()
                .or(() -> apps.stream()
                        .filter(app -> app.repo() != null && repoName(app.repo()).equals(name) && app.path() == null)
                        .findFirst())
                .map(App::code);
    }

    /** 이미지 저장소의 앱. 정확히 같은 이름만 */
    public Optional<String> appOfImage(String repository) {
        return apps.stream()
                .filter(app -> repository != null && repository.equals(app.image()))
                .findFirst()
                .map(App::code);
    }

    /** Logssey/service-backend처럼 소유자를 붙여 와도 레포 이름으로 본다 */
    private static String repoName(String repo) {
        return repo == null ? null : repo.substring(repo.lastIndexOf('/') + 1);
    }
}
