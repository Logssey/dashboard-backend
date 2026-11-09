package org.apache.catalina.realm;

import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/** Fixture stub with the same name/descriptor as Tomcat 11.0.24 (vulnerable prefix loop simplified). */
public abstract class RealmBase implements Realm {
    @Override
    public SecurityConstraint[] findSecurityConstraints(Request request, Context context) {
        SecurityConstraint[] constraints = context.findConstraints();
        if (constraints == null || constraints.length == 0) {
            return null; // what a default Spring Boot context hits on every request
        }
        int longest = -1;
        SecurityConstraint best = null;
        for (SecurityConstraint c : constraints) {
            for (SecurityCollection col : c.findCollections()) {
                for (String pattern : col.findPatterns()) {
                    if (pattern.endsWith("/*") && pattern.length() >= longest) { // the 11.0.24 bug: no '>= length' check
                        longest = pattern.length();
                        best = c;
                    }
                }
            }
        }
        return best == null ? null : new SecurityConstraint[] {best};
    }

    @Override
    public boolean hasResourcePermission(Request request, Response response, SecurityConstraint[] constraints, Context context) {
        return true;
    }
}
