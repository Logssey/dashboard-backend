package com.logssey.credential.scan;

/**
 * 스캔 한 번의 결과 ("지금 스캔" 응답).
 *
 * @param status         COMPLETED = 공유된 페이지를 모두 읽음 / PARTIAL = 일부 페이지를 못 읽음 /
 *                       NOT_CONFIGURED / FAILED. 못 읽은 페이지를 "키 0개"로 치지 않기 위해 PARTIAL을 따로 둔다
 * @param scannedPages   읽은 페이지 수
 * @param unreadablePages 목록에는 있었지만 읽지 못한 페이지 수 (공유가 끊김, 삭제 등)
 * @param foundKeys      발견한 키 수 (같은 키는 한 번)
 * @param newKeys        그중 처음 발견한 키 수
 * @param message        화면에 보여줄 안내 문구
 * @param scannedAt      스캔 시각 (ISO 8601 UTC)
 */
public record ScanResult(
        String status,
        int scannedPages,
        int unreadablePages,
        int foundKeys,
        int newKeys,
        String message,
        String scannedAt) {
}
