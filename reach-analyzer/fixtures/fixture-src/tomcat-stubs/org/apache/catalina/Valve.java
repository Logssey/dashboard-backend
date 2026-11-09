package org.apache.catalina;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

public interface Valve {
    void invoke(Request request, Response response);

    Valve getNext();

    void setNext(Valve valve);
}
