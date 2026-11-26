package com.logssey.overview;

/** 통합 현황에 모으는 보안 기능. link 는 각 기능 화면 */
public enum OverviewPart {
    SECRET("시크릿", "/secrets"),
    IAC("IaC 보안", "/iac"),
    VULNERABILITY("취약점 관리", "/vulnerabilities"),
    RUNTIME("런타임 보안", "/runtime"),
    COMPLIANCE("컴플라이언스", "/configuration"),
    CODE("코드 취약점", "/code"),
    /** 처음 만든 공통 탐지 이벤트 표(detection_events). 운영에는 행이 없고, 행이 있을 때만 보여 준다 */
    LEGACY("기존 탐지 이벤트", null);

    private final String label;
    private final String link;

    OverviewPart(String label, String link) {
        this.label = label;
        this.link = link;
    }

    public String label() {
        return label;
    }

    public String link() {
        return link;
    }
}
