package org.apache.tomcat.util.descriptor.web;

public class SecurityCollection {
    private final java.util.List<String> patterns = new java.util.ArrayList<>();
    private final java.util.List<String> methods = new java.util.ArrayList<>();

    public void addPattern(String pattern) {
        patterns.add(pattern);
    }

    public String[] findPatterns() {
        return patterns.toArray(new String[0]);
    }

    public void addMethod(String method) {
        methods.add(method);
    }

    public void addOmittedMethod(String method) {
        methods.add("!" + method);
    }
}
