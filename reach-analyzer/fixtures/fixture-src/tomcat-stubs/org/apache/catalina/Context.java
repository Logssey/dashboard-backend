package org.apache.catalina;

import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

public interface Context {
    void addConstraint(SecurityConstraint constraint);

    SecurityConstraint[] findConstraints();

    void setLoginConfig(LoginConfig config);

    Pipeline getPipeline();

    Realm getRealm();
}
