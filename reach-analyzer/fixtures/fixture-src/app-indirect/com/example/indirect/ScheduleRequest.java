package com.example.indirect;

import javax.xml.datatype.Duration;

/** javax.xml.datatype.Duration inside a nested record. */
public record ScheduleRequest(ScheduleRequest.Window window) {
    public record Window(String name, Duration length) {
    }
}
