package com.logssey.reach;

import com.logssey.reach.ci.ReachDispatchProperties;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.PropertySource;

/** Reach 설정(logssey.reach)을 읽는다. 공용 application.properties는 건드리지 않는다 */
@Configuration
@EnableConfigurationProperties({ReachProperties.class, ReachDispatchProperties.class})
public class ReachConfig {

    /**
     * local 프로필에서만 Re:Used 값을 쓴다. @PropertySource는 application.properties·환경 변수보다 우선순위가 낮아
     * 같은 키를 밖에서 주면 그 값이 이긴다
     */
    @Configuration
    @Profile("local")
    @PropertySource("classpath:reach/local-targets.properties")
    static class LocalTargets {
    }
}
