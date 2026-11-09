package com.example.risky;

import javax.xml.datatype.Duration;

public record MeasurementRequest(double value, Duration window) {
}
