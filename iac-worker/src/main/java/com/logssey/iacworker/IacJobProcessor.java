package com.logssey.iacworker;

/** One bean per job kind. It must finish its DB writes (through persistIfLeased) before returning. */
public interface IacJobProcessor {
    IacJobKind kind();

    void process(ClaimedIacJob job, IacJobExecutionService execution);
}
