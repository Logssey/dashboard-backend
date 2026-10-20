package com.logssey.credential.validation.notion;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.logssey.credential.validation.ValidationOutcome;
import com.logssey.credential.validation.ValidationReason;
import com.logssey.credential.validation.ValidationResult;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * 실제 Notion에 물어보는 확인용 테스트. 평소 .\gradlew test에서는 건너뛴다.
 *
 * 실행 방법 (cmd):
 *   set NOTION_LIVE_TEST=1
 *   .\gradlew test --tests "*NotionTokenValidatorLiveTest*"
 *
 * - 내 읽기 전용 수집기 토큰(.env의 NOTION_COLLECTOR_TOKEN)으로 VALID가 나오는지
 * - 형식만 맞춘 가짜 토큰으로 INVALID가 나오는지
 * 토큰은 .env에서 읽기만 하고 어디에도 출력하지 않는다. 페이지나 데이터는 읽지 않는다 (GET /v1/users/me만).
 */
@EnabledIfEnvironmentVariable(named = "NOTION_LIVE_TEST", matches = "1\\s*")
class NotionTokenValidatorLiveTest {

    private final NotionTokenValidator validator = new NotionTokenValidator("https://api.notion.com");

    @Test
    @DisplayName("실제 Notion: 내 수집기 토큰은 VALID (bot)")
    void myCollectorTokenIsValid() throws IOException {
        ValidationOutcome outcome = validator.validate(readEnv("NOTION_COLLECTOR_TOKEN"));

        assertThat(outcome.result()).isEqualTo(ValidationResult.VALID);
        assertThat(outcome.reason()).isEqualTo(ValidationReason.IDENTITY_CONFIRMED);
        assertThat(outcome.safeFacts()).containsEntry("principalType", "bot");
    }

    @Test
    @DisplayName("실제 Notion: 형식만 맞춘 가짜 토큰은 INVALID")
    void fakeTokenIsInvalid() {
        ValidationOutcome outcome = validator.validate("ntn_" + "0".repeat(46));

        assertThat(outcome.result()).isEqualTo(ValidationResult.INVALID);
        assertThat(outcome.reason()).isEqualTo(ValidationReason.INVALID_UNSPECIFIED);
    }

    private static String readEnv(String key) throws IOException {
        for (String line : Files.readAllLines(Path.of(".env"), StandardCharsets.UTF_8)) {
            String trimmed = line.strip();
            if (trimmed.startsWith(key + "=")) {
                String value = trimmed.substring(key.length() + 1).strip();
                if (value.length() >= 2 && (value.startsWith("\"") && value.endsWith("\"")
                        || value.startsWith("'") && value.endsWith("'"))) {
                    value = value.substring(1, value.length() - 1);
                }
                return value;
            }
        }
        throw new IllegalStateException(key + " is not set in .env");
    }
}
