package com.example.generic;

import javax.xml.datatype.Duration;

public record ScheduleRequest(String name, Duration every) {}
