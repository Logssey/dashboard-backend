package com.logssey.reach.query.dto;

/**
 * 통합 현황 보안 점수용 이미지 등급 (dashboard-design-docs ADR-D012 "이미지 등급"). API-04 목록·API-05 상세에 같이 준다.
 * grade: CRITICAL / HIGH / MEDIUM / LOW / UNASSESSED(스캐너 심각도 UNKNOWN). 분석 안 함(NOT_ANALYZED)은 도달 미확인으로 등급을 매긴다.
 * likelihood: 도달 × 실행으로 정한 가능성 HIGH / MEDIUM / LOW. 닿지 않음과 미평가는 null.
 * deduction: 등급 구간 안의 감점(CRITICAL 74~99, HIGH 48~73, MEDIUM 22~47, CVSS 비율). LOW·미평가는 null
 */
public record ReachFindingRisk(String grade, String likelihood, Integer deduction) {}
