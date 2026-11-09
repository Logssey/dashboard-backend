package org.apache.tomcat.util.descriptor.web;

public class SecurityConstraint {
    private final java.util.List<SecurityCollection> collections = new java.util.ArrayList<>();

    public void addCollection(SecurityCollection collection) {
        collections.add(collection);
    }

    public SecurityCollection[] findCollections() {
        return collections.toArray(new SecurityCollection[0]);
    }
}
