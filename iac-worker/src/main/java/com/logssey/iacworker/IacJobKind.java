package com.logssey.iacworker;

/** Kinds the worker executes. COLLECT_GRAPH rows only record the Cartography CronJob and are never claimed. */
public enum IacJobKind {
    ANALYZE_RUN,
    ENRICH_GRAPH,
    CHECK_DRIFT,
    CHECK_STATE
}
