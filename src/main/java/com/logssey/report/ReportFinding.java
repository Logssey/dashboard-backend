package com.logssey.report;

import java.time.OffsetDateTime;

/**
 * Finding 한 건의 공통 필드 (양식 "Finding 한 건 표기 형식").
 * 비밀값·계정 ID·내부 IP·인스턴스 ID·ARN·시크릿 이름은 넣지 않는다 (양식 "표기·보안 규칙").
 *
 * @param severity   CRITICAL · HIGH · MEDIUM · LOW · UNASSESSED
 * @param response   공통 상태 (미조치 · 조치 중 · 재검사 대기 · 해결 · 예외 승인)와 대응을 한 줄로
 * @param dueAt      담당자가 정한 기한. 없으면 공통 기능이 기본값으로 채우고 dueDefault 를 true 로 둔다
 * @param link       대시보드 상세 화면 경로
 */
public record ReportFinding(String id, String title, String severity, String response, String asset,
                            String location, String evidence, OffsetDateTime foundAt, OffsetDateTime dueAt,
                            boolean dueDefault, String assignee, String action, String link) {

    public ReportFinding withDue(OffsetDateTime due, boolean byDefault) {
        return new ReportFinding(id, title, severity, response, asset, location, evidence, foundAt, due, byDefault,
                assignee, action, link);
    }
}
