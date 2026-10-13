package com.logssey.secretworker.detector;

import java.util.List;

public record GitleaksScanResult(String engineVersion, String configHash, List<GitleaksFinding> findings) {
    public GitleaksScanResult {
        findings = List.copyOf(findings);
    }
}
