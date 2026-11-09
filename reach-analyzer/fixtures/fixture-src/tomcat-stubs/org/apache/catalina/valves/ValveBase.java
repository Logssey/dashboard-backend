package org.apache.catalina.valves;

import org.apache.catalina.Valve;

public abstract class ValveBase implements Valve {
    protected Valve next;

    @Override
    public Valve getNext() {
        return next;
    }

    @Override
    public void setNext(Valve valve) {
        next = valve;
    }
}
