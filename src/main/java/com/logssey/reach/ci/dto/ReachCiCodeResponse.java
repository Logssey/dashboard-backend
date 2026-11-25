package com.logssey.reach.ci.dto;

/** 러너가 받을 Reach 코드 (분석기·판정 데이터·CI 스크립트). commit은 대시보드가 지금 돌리는 dashboard-backend 커밋(40자) */
public record ReachCiCodeResponse(String commit) {
}
