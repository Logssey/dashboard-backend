package org.apache.catalina;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

public interface Realm {
    SecurityConstraint[] findSecurityConstraints(Request request, Context context);

    boolean hasResourcePermission(Request request, Response response, SecurityConstraint[] constraints, Context context);
}
