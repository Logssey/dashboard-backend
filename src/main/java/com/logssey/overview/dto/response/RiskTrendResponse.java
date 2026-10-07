package com.logssey.overview.dto.response;

import java.util.List;

public record RiskTrendResponse(List<DayCount> days) {

    public record DayCount(String date, long total, long critical, long high, long medium, long low) {
    }
}
