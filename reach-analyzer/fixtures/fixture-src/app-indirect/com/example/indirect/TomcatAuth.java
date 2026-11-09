package com.example.indirect;

import jakarta.servlet.HttpMethodConstraintElement;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import org.apache.catalina.authenticator.DigestAuthenticator;
import org.apache.catalina.authenticator.FormAuthenticator;

/** Container auth through subclasses and the Servlet security API instead of `new`. */
public final class TomcatAuth {
    private TomcatAuth() {
    }

    public static class TunedDigestAuthenticator extends DigestAuthenticator {
    }

    public static class AuditedFormAuthenticator extends FormAuthenticator {
    }

    public static HttpMethodConstraintElement postOnly() {
        return new HttpMethodConstraintElement("POST");
    }

    @ServletSecurity(@HttpConstraint(rolesAllowed = "admin"))
    public static class AdminExport {
    }
}
