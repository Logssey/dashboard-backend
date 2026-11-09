package org.springframework.boot.tomcat;

import org.apache.catalina.Context;

@FunctionalInterface
public interface TomcatContextCustomizer {
    void customize(Context context);
}
