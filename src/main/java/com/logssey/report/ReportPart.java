package com.logssey.report;

/** 리포트에 들어가는 파트. 순서가 곧 리포트의 장 순서다. */
public enum ReportPart {
    IAC("IaC 보안", "/iac"),
    SECRET("시크릿", "/secrets"),
    VULNERABILITY("취약점(이미지·공급망)", "/vulnerabilities"),
    RUNTIME("런타임 보안", "/runtime");

    private final String label;
    private final String path;

    ReportPart(String label, String path) {
        this.label = label;
        this.path = path;
    }

    public String label() {
        return label;
    }

    /** 대시보드에서 이 파트의 화면 경로 */
    public String path() {
        return path;
    }
}
