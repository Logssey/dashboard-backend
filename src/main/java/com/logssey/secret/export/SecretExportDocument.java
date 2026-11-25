package com.logssey.secret.export;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * 변환기에 넘기는 내보내기 묶음.
 * filters에는 검색어 원문을 넣지 않는다(검색어 사용 여부만 hasSearch로 남긴다).
 */
public record SecretExportDocument(OffsetDateTime generatedAt, OffsetDateTime asOf, boolean restrictedCoverage,
                                   Map<String, String> filters, int keyCount, List<SecretExportRecord> records) {
}
