package com.logssey.iacworker.graph;

import java.util.List;

/** Cartography 는 CloudFront origin 을 저장하지 않아 AWS 에서 직접 읽는다. */
public interface CloudFrontOrigins {

    /** 배포 ARN 과 그 origin 도메인 이름. */
    record Origin(String distributionArn, String domainName) {
    }

    List<Origin> list();
}
