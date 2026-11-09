package org.apache.catalina.authenticator;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.connector.Request;

public final class NonLoginAuthenticator extends AuthenticatorBase {
    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response) {
        return true;
    }
}
