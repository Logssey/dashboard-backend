package com.logssey.report;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * 저장되는 리포트 본문 (스냅샷). 파트 하나만 담는다.
 * 화면·인쇄 순서: 1 처리 우선순위 → 2 발견된 취약점 → 3 조치 방안 → 4 부록
 */
public record ReportContent(String name, ReportPart part, LocalDate periodFrom, LocalDate periodTo,
                            OffsetDateTime createdAt, String createdBy, Overview overview,
                            Vulnerabilities vulnerabilities, Remediation remediation, List<Priority> priorities,
                            Appendix appendix) {

    /** 표지와 머리에 쓰는 값. connected 가 false 면 파트 데이터가 아직 연결되지 않은 리포트다 (빈칸은 0건이 아님) */
    public record Overview(boolean connected, OffsetDateTime dataAsOf, boolean stale, String headline,
                           ReportChapter.Metric keyMetric, Long newInPeriod, Long resolvedInPeriod, String note) {
    }

    /** 1 발견된 취약점 */
    public record Vulnerabilities(String unit, Map<String, Long> severityCounts, long overdue, long dueSoon,
                                  long byDefault, List<ReportFinding> findings) {
    }

    /** 3 공통 조치 방안: 여러 취약점에 함께 적용되는 조치(해결하는 취약점이 많은 순) + AI 전체 조치 계획 */
    public record Remediation(List<Action> actions, ReportAdvice advice) {
    }

    /** 공통 조치 하나. findingIds 는 이 조치로 해결되는 취약점 (조치 문장에 이 조치 이름이 나오는 건) */
    public record Action(int rank, String title, String how, String impact, String link, List<String> findingIds) {
    }

    /** 3 처리 우선순위의 한 줄 */
    public record Priority(int rank, ReportFinding finding, boolean overdue) {
    }

    /** 4 부록 */
    public record Appendix(List<ReportChapter.Item> scope, List<String> criteria, List<ReportChapter.Link> links) {
    }
}
