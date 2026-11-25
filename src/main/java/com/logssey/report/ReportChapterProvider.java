package com.logssey.report;

import java.time.OffsetDateTime;

/**
 * 파트가 자기 장을 넘기는 곳. 파트마다 하나를 스프링 빈으로 만든다.
 * 제공하지 않는 파트의 장은 공통 기능이 "파트 연결 전"으로 채운다.
 */
public interface ReportChapterProvider {

    ReportPart part();

    /** 기간은 신규·해결 건수를 셀 때만 쓴다. 위험도 분포와 Finding 은 지금 열린 것 기준이다. */
    ReportChapter chapter(OffsetDateTime periodFrom, OffsetDateTime periodTo, String loginId);
}
