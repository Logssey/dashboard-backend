package org.apache.catalina;

public interface Pipeline {
    void addValve(Valve valve);

    Valve getFirst();
}
