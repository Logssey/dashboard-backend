package org.apache.catalina.connector;

import org.apache.catalina.Session;

public class Request {
    private String method = "GET";
    private Session session;

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Session getSessionInternal(boolean create) {
        return session;
    }
}
