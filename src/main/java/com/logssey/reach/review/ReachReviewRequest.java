package com.logssey.reach.review;

/**
 * API-06 본문. 값 검사는 Service의 validate()가 한다 (record 생성자에서 던지면 Jackson이 다른 예외로 감싼다).
 * version이 Integer인 것은 빠졌을 때 0이 아니라 null로 받아 400을 주려는 것이다.
 */
public record ReachReviewRequest(
        String reviewState,
        String status,
        String note,
        Proposal proposal,
        Integer version) {

    /** 확정 전 판정 제안. reviewState가 UNREVIEWED일 때만 받는다 (API 명세 3-10) */
    public record Proposal(String status, String summary, String reference) {}
}
