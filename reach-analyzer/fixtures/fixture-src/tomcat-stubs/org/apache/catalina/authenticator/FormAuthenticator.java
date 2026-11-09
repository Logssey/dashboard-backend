package org.apache.catalina.authenticator;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;

/** Fixture stub with Tomcat 11.0.24 names/descriptors. */
public class FormAuthenticator extends AuthenticatorBase {
    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response) {
        Session session = request.getSessionInternal(true);
        return session != null && restoreRequest(request, session);
    }

    protected boolean restoreRequest(Request request, Session session) {
        Object saved = session.getNote("org.apache.catalina.authenticator.REQUEST");
        if (saved instanceof String method) {
            request.setMethod(method); // 11.0.24: constraints are not re-evaluated after this
            return true;
        }
        return false;
    }
}
