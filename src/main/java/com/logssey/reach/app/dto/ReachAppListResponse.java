package com.logssey.reach.app.dto;

import java.util.List;

/** API-14 감시 대상 앱 목록. 설정(logssey.reach.apps) 순서 그대로, 없으면 빈 배열 */
public record ReachAppListResponse(List<Item> items) {

    /** repo·path·image는 설정에 없으면 null */
    public record Item(String code, String repo, String path, String image) {}
}
