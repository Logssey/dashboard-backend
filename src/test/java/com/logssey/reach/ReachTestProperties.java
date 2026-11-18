package com.logssey.reach;

import java.util.List;

import com.logssey.reach.ReachProperties.App;
import com.logssey.reach.ReachProperties.L1;

/** 테스트용 Reach 설정. Re:Used 값은 src/main/resources/reach/local-targets.properties와 같다 */
public final class ReachTestProperties {

    public static final List<App> REUSED_APPS = List.of(
            new App("API", "service-backend", null, "logssey/reused-api"),
            new App("WEB", "service-frontend", null, "logssey/reused-web", "npm"),
            new App("CHAT", "service-backend", "chat-server", "logssey/reused-chat", "npm"));

    public static final ReachProperties REUSED = new ReachProperties(REUSED_APPS, new L1("reused-prod", List.of("reused")));

    /** Re:Used 앱에 L1 범위만 바꾼 설정 */
    public static ReachProperties withL1(String cluster, List<String> namespaces) {
        return new ReachProperties(REUSED_APPS, new L1(cluster, namespaces));
    }

    private ReachTestProperties() {}
}
