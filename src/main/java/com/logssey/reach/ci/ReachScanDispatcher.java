package com.logssey.reach.ci;

import java.util.Map;

/** 스캔을 실행할 러너를 띄운다 (API-01 → 서비스 레포의 Reach 워크플로). 테스트는 가짜로 바꾼다 */
interface ReachScanDispatcher {

    /** 설정이 있어 띄울 수 있는지. 없으면 스캔은 QUEUED로 남는다 */
    boolean enabled();

    /**
     * repository(소유자 없는 레포 이름)의 워크플로를 inputs로 띄운다.
     * 띄우지 못하면 ReachUnavailableException (503, 요청한 트랜잭션은 되돌아간다)
     */
    void dispatch(String repository, Map<String, String> inputs);

    /** 띄우지 않는다 (설정 없음) */
    ReachScanDispatcher NONE = new ReachScanDispatcher() {
        @Override
        public boolean enabled() {
            return false;
        }

        @Override
        public void dispatch(String repository, Map<String, String> inputs) {
            throw new IllegalStateException("dispatch is not configured");
        }
    };
}
