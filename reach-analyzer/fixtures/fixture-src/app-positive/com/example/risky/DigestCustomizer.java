package com.example.risky;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.DigestAuthenticator;
import org.springframework.boot.tomcat.TomcatContextCustomizer;
import org.springframework.stereotype.Component;

/** Container-managed DIGEST auth (CVE-2026-65905). */
@Component
public class DigestCustomizer implements TomcatContextCustomizer {
    @Override
    public void customize(Context context) {
        context.getPipeline().addValve(new DigestAuthenticator());
    }
}
