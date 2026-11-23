package com.logssey.report;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * 파트가 리포트에 넘기는 데이터. 공통 기능이 이것으로 4개 절(발견된 취약점, 조치 방안, 처리 우선순위, 부록)을 만든다.
 * findings 는 기준 시각에 열려 있는 건 전부다.
 *
 * @param dataAsOf     파트 데이터의 기준 시각 (마지막 수집·스캔). 모르면 null
 * @param unit         이 파트가 세는 단위 (예: "열린 경로 · 매일 점검 발견 건")
 * @param remediations 파트가 정한 조치 방안 (규칙 기반)
 * @param links        부록에 넣을 참고 링크 (규칙 문서, 조치 안내 등)
 * @param newInPeriod  보고 기간 안 신규 건수. 파트가 세지 않으면 null
 */
public record ReportChapter(ReportPart part, OffsetDateTime dataAsOf, String headline, String unit, Metric keyMetric,
                            List<Item> scope, Map<String, Long> severityCounts, List<ReportFinding> findings,
                            List<Remediation> remediations, List<Link> links, List<String> criteria,
                            Long newInPeriod, Long resolvedInPeriod, String note) {

    /** 장을 아직 제공하지 않는 파트. 각 파트가 ReportChapterProvider 를 구현하면 실제 값으로 바뀐다 */
    public static ReportChapter notConnected(ReportPart part) {
        return new ReportChapter(part, null, "이 파트는 아직 리포트 데이터를 연결하지 않았습니다.", "—", null, List.of(),
                Map.of(), List.of(), List.of(), List.of(), List.of(), null, null,
                "빈칸은 0건이 아니라 데이터가 연결되지 않았다는 뜻입니다. 파트 화면에서 현황을 확인하세요.");
    }

    /** 이름과 값 한 쌍 (범위 표의 한 줄) */
    public record Item(String label, String value) {
    }

    /** 파트가 고른 핵심 숫자 하나 */
    public record Metric(String label, long value) {
    }

    /** 조치 방안 하나. impact 는 이 조치로 줄어드는 것 (예: "열린 경로 54개 닫힘") */
    public record Remediation(String title, String how, String impact, String link) {
    }

    /** 참고 링크. url 은 대시보드 경로(/iac) 또는 https 주소 */
    public record Link(String label, String url) {
    }
}
