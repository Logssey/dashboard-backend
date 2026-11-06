package com.logssey.secretworker.notion;

import java.time.Instant;

/** Carries only registered failure codes and bounded retry metadata. */
public final class NotionSourceException extends RuntimeException {
  public enum Code {
    CONFIGURATION_ERROR,
    ACCESS_DENIED,
    NOT_FOUND,
    RATE_LIMITED,
    PROVIDER_ACCESS_BLOCKED,
    SOURCE_UNAVAILABLE,
    TIMEOUT,
    MALFORMED_RESPONSE,
    RESPONSE_TOO_LARGE,
    IN_TRASH,
    CONTENT_CHANGED,
    UNSUPPORTED_BLOCK,
    BLOCK_LIMIT,
    DEPTH_LIMIT,
    TEXT_LIMIT,
    REQUEST_LIMIT,
    CURSOR_LOOP
  }

  private final Code code;
  private final int status;
  private final Instant retryAt;

  public NotionSourceException(Code code, int status, Instant retryAt) {
    super(code.name());
    this.code = code;
    this.status = status;
    this.retryAt = retryAt;
  }

  public NotionSourceException(Code code, int status) {
    this(code, status, null);
  }

  public Code code() {
    return code;
  }

  public int status() {
    return status;
  }

  public Instant retryAt() {
    return retryAt;
  }
}
