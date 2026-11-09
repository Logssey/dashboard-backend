package com.example.risky;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.boot.tomcat.TomcatContextCustomizer;
import org.springframework.stereotype.Component;

/** Container-managed FORM auth with a POST-only constraint (CVE-2026-68525) and app-added constraints (CVE-2026-65182). */
@Component
public class TomcatSecurityCustomizer implements TomcatContextCustomizer {
    @Override
    public void customize(Context context) {
        SecurityCollection admin = new SecurityCollection();
        admin.addPattern("/admin/reports/*");
        admin.addPattern("/admin/*");
        admin.addMethod("POST");
        SecurityConstraint constraint = new SecurityConstraint();
        constraint.addCollection(admin);
        context.addConstraint(constraint);
        context.getPipeline().addValve(new FormAuthenticator());
    }
}
