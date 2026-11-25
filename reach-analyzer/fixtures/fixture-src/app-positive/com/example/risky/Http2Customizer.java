package com.example.risky;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http2.Http2Protocol;
import org.springframework.boot.tomcat.TomcatConnectorCustomizer;
import org.springframework.stereotype.Component;

/** Turns HTTP/2 on in code (CVE-2026-65637). Whether Tomcat also terminates TLS is not visible here. */
@Component
public class Http2Customizer implements TomcatConnectorCustomizer {
    @Override
    public void customize(Connector connector) {
        connector.addUpgradeProtocol(new Http2Protocol());
    }
}
