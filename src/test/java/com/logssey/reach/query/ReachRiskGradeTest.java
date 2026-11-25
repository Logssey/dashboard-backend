package com.logssey.reach.query;

import java.math.BigDecimal;

import com.logssey.reach.query.dto.ReachFindingRisk;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/** 이미지 등급 결정표와 CVSS 감점 (ADR-D012 결정 1 "이미지 등급") */
class ReachRiskGradeTest {

    /** 가능성(도달 × 실행) × 영향(스캐너 심각도) 3×3. CVSS가 없으면 구간 맨 위 값 */
    @ParameterizedTest
    @CsvSource(nullValues = "-", value = {
            // 닿음 + 실행 중 = 가능성 HIGH
            "REACHABLE,   RUNNING,     CRITICAL, CRITICAL, HIGH,   99",
            "REACHABLE,   RUNNING,     HIGH,     CRITICAL, HIGH,   99",
            "REACHABLE,   RUNNING,     MEDIUM,   HIGH,     HIGH,   73",
            "REACHABLE,   RUNNING,     LOW,      MEDIUM,   HIGH,   47",
            // 닿음 + 실행 미확인, 도달 미확인 + 실행 중 = 가능성 MEDIUM
            "REACHABLE,   NOT_RUNNING, CRITICAL, HIGH,     MEDIUM, 73",
            "REACHABLE,   UNKNOWN,     MEDIUM,   MEDIUM,   MEDIUM, 47",
            "UNKNOWN,     RUNNING,     HIGH,     HIGH,     MEDIUM, 73",
            "UNKNOWN,     RUNNING,     LOW,      LOW,      MEDIUM, -",
            // 도달 미확인 + 실행 미확인 = 가능성 LOW
            "UNKNOWN,     NOT_RUNNING, CRITICAL, MEDIUM,   LOW,    47",
            "UNKNOWN,     UNKNOWN,     MEDIUM,   LOW,      LOW,    -",
    })
    void decisionTable(String status, String deployment, String severity, String grade, String likelihood,
                       Integer deduction) {
        assertThat(ReachRiskGrade.of(severity, status, deployment, null))
                .isEqualTo(new ReachFindingRisk(grade, likelihood, deduction));
    }

    @Test
    void unreachableIsLowWhateverTheSeverity() {
        assertThat(ReachRiskGrade.of("CRITICAL", "UNREACHABLE", "RUNNING", new BigDecimal("9.8")))
                .isEqualTo(new ReachFindingRisk("LOW", null, null));
    }

    @Test
    void unknownSeverityIsUnassessed() {
        var unassessed = new ReachFindingRisk(ReachRiskGrade.UNASSESSED, null, null);
        assertThat(ReachRiskGrade.of("UNKNOWN", "REACHABLE", "RUNNING", null)).isEqualTo(unassessed);
        assertThat(ReachRiskGrade.of("UNKNOWN", "NOT_ANALYZED", "RUNNING", null)).isEqualTo(unassessed);
        assertThat(ReachRiskGrade.of(null, "REACHABLE", "RUNNING", null)).isEqualTo(unassessed);
    }

    /** 분석 안 함은 도달 미확인과 같은 줄이다. 그래서 분석 안 한 LOW가 닿고 실행 중인 MEDIUM보다 위로 가지 않는다 */
    @Test
    void notAnalyzedIsGradedLikeAnUnknownReach() {
        assertThat(ReachRiskGrade.of("CRITICAL", "NOT_ANALYZED", "RUNNING", new BigDecimal("9.8")))
                .isEqualTo(ReachRiskGrade.of("CRITICAL", "UNKNOWN", "RUNNING", new BigDecimal("9.8")))
                .isEqualTo(new ReachFindingRisk("HIGH", "MEDIUM", 71));
        assertThat(ReachRiskGrade.of("LOW", "NOT_ANALYZED", "RUNNING", null)).isEqualTo(new ReachFindingRisk("LOW", "MEDIUM", null));
        assertThat(ReachRiskGrade.of("MEDIUM", "REACHABLE", "RUNNING", new BigDecimal("4.0")).deduction()).isEqualTo(48);
        assertThat(ReachRiskGrade.of("HIGH", "NOT_ANALYZED", "NOT_RUNNING", null)).isEqualTo(new ReachFindingRisk("MEDIUM", "LOW", 47));
    }

    /** 구간 아래 + (CVSS − 범위 아래) ÷ 범위 폭 × 25. 범위 밖은 구간 끝으로 자른다 */
    @ParameterizedTest
    @CsvSource({
            "REACHABLE, RUNNING, CRITICAL, 10.0, 99",
            "REACHABLE, RUNNING, CRITICAL, 9.8,  97",
            "REACHABLE, RUNNING, HIGH,     7.5,  78",
            "REACHABLE, RUNNING, HIGH,     7.0,  74",
            "UNKNOWN,   RUNNING, CRITICAL, 9.8,  71",
            "REACHABLE, RUNNING, MEDIUM,   5.3,  59",
            "UNKNOWN,   RUNNING, MEDIUM,   5.3,  33",
            "REACHABLE, RUNNING, HIGH,     9.9,  98",
            // 심각도와 CVSS 출처가 달라 범위를 벗어나면 구간 끝
            "REACHABLE, RUNNING, HIGH,     5.0,  74",
            "UNKNOWN,   RUNNING, MEDIUM,   9.0,  47",
    })
    void cvssPlacesTheDeductionInsideTheBand(String status, String deployment, String severity, String cvss,
                                             int deduction) {
        assertThat(ReachRiskGrade.of(severity, status, deployment, new BigDecimal(cvss)).deduction()).isEqualTo(deduction);
    }
}
