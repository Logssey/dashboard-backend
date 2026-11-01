package com.logssey.reach.export.dto;

import java.time.OffsetDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * API-11 공통 Finding(OCSF) 한 건 (Reach API 명세 5-3, 팀 합의 전 제안).
 * OCSF 필드 이름이라 Reach API의 camelCase 대신 snake_case다. 숫자 필드(클래스 번호, severity_id, 스키마 버전)는
 * 합의 때 채우려고 5-3처럼 넣지 않는다. Reach 고유 값은 확장 위치 후보인 unmapped.reach에 둔다
 */
public record ReachOcsfFindingResponse(
        @JsonProperty("class_name") String className,
        Metadata metadata,
        OffsetDateTime time,                                          // 스캔이 끝난 시각
        @JsonProperty("finding_info") FindingInfo findingInfo,
        List<Vulnerability> vulnerabilities,
        List<Resource> resources,
        Unmapped unmapped) {

    public record Metadata(Product product) {}

    public record Product(String name, @JsonProperty("vendor_name") String vendorName) {}

    /** uid는 Reach Finding id를 문자열로 */
    public record FindingInfo(String uid, String title) {}

    public record Vulnerability(Cve cve, @JsonProperty("affected_packages") List<AffectedPackage> affectedPackages) {}

    public record Cve(String uid) {}

    public record AffectedPackage(String name, String version, String purl) {}

    /** 이미지는 저장소@digest, 레포는 이름[/하위 경로]@커밋 */
    public record Resource(String uid) {}

    public record Unmapped(Reach reach) {}

    /** status·method·summary는 내보낸 스캔의 도구 판정, reviewState는 지금의 검토 상태 */
    public record Reach(String severity, String status, String method, String summary, String reviewState,
                        String deployment, String findingUrl) {}
}
