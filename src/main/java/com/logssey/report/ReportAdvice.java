package com.logssey.report;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * AI가 만든 대응 추천. 리포트 전체(조치 방안 절)와 취약점 한 건(취약점 표의 'AI 대응 방법')에 같은 모양을 쓴다.
 * 읽기 쉽게 문장이 아니라 짧은 불릿으로 받는다.
 *
 * @param status  GENERATED · DISABLED(설정 꺼짐) · FAILED(호출 실패·거절·형식 오류)
 * @param reason  DISABLED·FAILED 일 때 이유 코드 (예: KEY_MISSING, PROVIDER_TIMEOUT)
 * @param request 사용자가 입력창에 적은 내용 (없으면 null)
 * @param points  핵심 요약 불릿
 */
public record ReportAdvice(String status, String reason, String model, String request, List<String> points,
                           List<Item> items, OffsetDateTime generatedAt) {

    public static final String GENERATED = "GENERATED";
    public static final String DISABLED = "DISABLED";
    public static final String FAILED = "FAILED";

    /** 추천 하나: 제목, 왜 하는지 한 줄, 단계 */
    public record Item(String title, String why, List<String> steps) {
    }

    public static ReportAdvice notGenerated(String status, String reason, String model, String request) {
        return new ReportAdvice(status, reason, model, request, List.of(), List.of(), null);
    }
}
