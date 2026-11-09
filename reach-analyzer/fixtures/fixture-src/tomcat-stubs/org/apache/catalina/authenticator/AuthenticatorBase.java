package org.apache.catalina.authenticator;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/** Fixture stub: the container calls invoke() for every request (framework-invoked). */
public abstract class AuthenticatorBase extends ValveBase {
    protected Context context;

    public void setContext(Context context) {
        this.context = context;
    }

    @Override
    public void invoke(Request request, Response response) {
        Realm realm = context.getRealm();
        SecurityConstraint[] constraints = realm.findSecurityConstraints(request, context);
        if (constraints == null) {
            if (next != null) next.invoke(request, response);
            return;
        }
        if (!doAuthenticate(request, response)) {
            return;
        }
        if (realm.hasResourcePermission(request, response, constraints, context) && next != null) {
            next.invoke(request, response);
        }
    }

    protected abstract boolean doAuthenticate(Request request, HttpServletResponse response);
}
