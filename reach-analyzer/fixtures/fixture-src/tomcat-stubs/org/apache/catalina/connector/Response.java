package org.apache.catalina.connector;

import jakarta.servlet.http.HttpServletResponse;

public class Response implements HttpServletResponse {
    private int status = 200;

    @Override
    public void setStatus(int sc) {
        status = sc;
    }
}
