package com.logssey.credential.scan;

/**
 * 스캔 한 번의 결과 ("지금 스캔" 응답).
 *
 * @param status       COMPLETED / NOT_CONFIGURED / FAILED
 * @param scannedPages 읽은 페이지 수
 * @param foundKeys    발견한 키 수 (같은 키는 한 번)
 * @param newKeys      그중 처음 발견한 키 수
 * @param newEvents    새로 등록한 탐지 수 (scanNow만. 서버 시작 시 수집은 0)
 * @param message      화면에 보여줄 안내 문구
 * @param scannedAt    스캔 시각 (ISO 8601 UTC)
 */
public record ScanResult(
        String status,
        int scannedPages,
        int foundKeys,
        int newKeys,
        int newEvents,
        String message,
        String scannedAt) {

    ScanResult withNewEvents(int events, String newMessage) {
        return new ScanResult(status, scannedPages, foundKeys, newKeys, events, newMessage, scannedAt);
    }
}
