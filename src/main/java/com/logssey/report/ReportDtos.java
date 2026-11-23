package com.logssey.report;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;

/** 리포트 API 요청·응답 */
public final class ReportDtos {

    private ReportDtos() {
    }

    /** 새 리포트 화면이 쓰는 값: 장을 제공하는 파트와 AI 추천을 쓸 수 있는지 */
    public record Options(List<ReportPart> connectedParts, boolean aiEnabled) {
    }

    /**
     * parts 하나마다 리포트가 하나씩 만들어진다. name 이 비면 "[파트명] 보안 리포트 기간"으로 만든다.
     * aiRequest 는 조치 방안 추천에 참고할 내용 (선택)
     */
    public record CreateRequest(String name, LocalDate periodFrom, LocalDate periodTo, List<String> parts,
                                String aiRequest) {
    }

    public record Created(List<Long> reportIds) {
    }

    /** connected 가 false 면 데이터 연결 전 리포트라 critical 은 의미가 없다 */
    public record ListItem(long reportId, ReportPart part, String name, LocalDate periodFrom, LocalDate periodTo,
                           long critical, long overdue, boolean connected, OffsetDateTime createdAt, String createdBy) {
    }

    /** findingAdvice: 취약점별로 이미 만든 AI 대응 방법 (finding ID → 대응 방법) */
    public record Detail(long reportId, ReportContent content, java.util.Map<String, ReportAdvice> findingAdvice) {
    }
}
