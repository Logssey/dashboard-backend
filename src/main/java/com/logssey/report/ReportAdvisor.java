package com.logssey.report;

/** 대응 추천. 파트 데이터는 리포트에 이미 실린 값(식별자 없음)만 받는다. */
public interface ReportAdvisor {

    /** 설정이 갖춰져 지금 호출할 수 있으면 true */
    boolean enabled();

    /** 리포트 전체에 대한 조치 방안 (조치 방안 절) */
    ReportAdvice advise(ReportChapter chapter, String request);

    /** 취약점 한 건에 대한 대응 방법 (취약점 표의 'AI 대응 방법') */
    ReportAdvice adviseFinding(ReportPart part, ReportFinding finding, java.util.List<ReportChapter.Remediation> actions,
                               String request);
}
