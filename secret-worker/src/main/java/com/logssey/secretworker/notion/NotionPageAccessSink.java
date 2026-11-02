package com.logssey.secretworker.notion;

/** Called inside the scope's fenced persistence callback after a successful collection. */
public interface NotionPageAccessSink {
    void observe(NotionPageAccessObservation observation);
}
