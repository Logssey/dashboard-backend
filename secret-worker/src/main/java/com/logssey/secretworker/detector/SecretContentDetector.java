package com.logssey.secretworker.detector;

/** One in-memory collected object in, sanitized finding positions out. */
public interface SecretContentDetector {
    String engineVersion();
    String configHash();
    GitleaksScanResult scan(byte[] content);
}
