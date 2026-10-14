package com.logssey.secret.connection;

record ConnectionProbeResult(String status, String reasonCode) {
    static ConnectionProbeResult connected() { return new ConnectionProbeResult("CONNECTED", null); }
    static ConnectionProbeResult failed(String code) { return new ConnectionProbeResult("FAILED", code); }
    static ConnectionProbeResult unavailable(String code) { return new ConnectionProbeResult("UNAVAILABLE", code); }
}
