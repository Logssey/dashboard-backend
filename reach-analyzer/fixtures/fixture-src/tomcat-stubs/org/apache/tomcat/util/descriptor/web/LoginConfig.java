package org.apache.tomcat.util.descriptor.web;

public class LoginConfig {
    private final String authMethod;

    public LoginConfig(String authMethod, String realmName, String loginPage, String errorPage) {
        this.authMethod = authMethod;
    }

    public String getAuthMethod() {
        return authMethod;
    }
}
