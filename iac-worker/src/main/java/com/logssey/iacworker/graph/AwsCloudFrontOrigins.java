package com.logssey.iacworker.graph;

import java.util.ArrayList;
import java.util.List;

import software.amazon.awssdk.services.cloudfront.CloudFrontClient;

/** cloudfront:ListDistributions 만 쓴다 (읽기 전용). */
public class AwsCloudFrontOrigins implements CloudFrontOrigins {

    private static final int MAX_PAGES = 100;

    private final CloudFrontClient client;

    public AwsCloudFrontOrigins(CloudFrontClient client) {
        this.client = client;
    }

    @Override
    public List<Origin> list() {
        List<Origin> origins = new ArrayList<>();
        String marker = null;
        for (int page = 0; page < MAX_PAGES; page++) {
            String current = marker;
            var list = client.listDistributions(request -> request.marker(current)).distributionList();
            if (list == null) break;
            for (var distribution : list.items()) {
                for (var origin : distribution.origins().items()) {
                    origins.add(new Origin(distribution.arn(), origin.domainName()));
                }
            }
            if (!Boolean.TRUE.equals(list.isTruncated())) break;
            marker = list.nextMarker();
        }
        return origins;
    }
}
