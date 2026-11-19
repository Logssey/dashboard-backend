package org.springframework.boot.tomcat;

import org.apache.catalina.connector.Connector;

@FunctionalInterface
public interface TomcatConnectorCustomizer {
    void customize(Connector connector);
}
