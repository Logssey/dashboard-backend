package com.logssey.overview.dto.response;

import java.util.List;

public record AssetSummaryResponse(long totalCount, List<ProviderCount> providers) {

    public record ProviderCount(String provider, String description, long count) {
    }
}
