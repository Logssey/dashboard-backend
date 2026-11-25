package com.logssey.overview.score;

import java.time.Instant;
import java.util.List;

import com.logssey.overview.OverviewPart;

/**
 * 보안 점수에 결과를 넘기는 기능 하나 (dashboard-design-docs ADR-D012 결정 8 "기능이 넘겨줄 것").
 * 기능은 지금 열린 위험(ADR-D011 결정 1과 같은 범위)을 자원 단위로 넘기고, 점수 계산은 {@link SecurityScoreCalculator}가 한다.
 * 운영 환경만 넘긴다. 읽기만 하고 기능의 판정 규칙은 바꾸지 않는다
 */
public interface ScoreSource {

    OverviewPart part();

    /** 보는 사람 권한이 필요한 기능(Secret)만 login을 쓴다 */
    Result read(String login);

    /**
     * 결과가 어느 자산의 것인지 알려 주는 단서. 계산기가 설정(score-assets.json)으로 자산에 잇는다.
     * ARN: AWS 자원 ARN, APP: 앱 코드(API·WEB·CHAT), REPO: 레포와 파일 경로, NONE: 모름(그 기능의 미분류)
     */
    record Hint(String type, String value, String path) {
        public static final Hint NONE = new Hint("NONE", null, null);

        public static Hint arn(String arn) {
            return arn == null || arn.isBlank() ? NONE : new Hint("ARN", arn, null);
        }

        public static Hint app(String app) {
            return app == null || app.isBlank() ? NONE : new Hint("APP", app, null);
        }

        public static Hint repo(String repository, String path) {
            return repository == null || repository.isBlank() ? NONE : new Hint("REPO", repository, path);
        }
    }

    /**
     * 열린 위험 한 건. grade는 공통 등급(CRITICAL·HIGH·MEDIUM·LOW·UNASSESSED).
     * deduction은 등급 구간 안의 감점이다(ADR-D012 "등급 안 세분화"). 근거가 없으면 null이고 구간 맨 위 값을 쓴다.
     * firstSeenAt은 처음 발견 시각이다. 모르면 null이고 기한 지표에서 빠진다
     */
    record Finding(String key, String title, String grade, Integer deduction, Hint hint, Instant firstSeenAt) {}

    /**
     * 이 기능이 어디까지 검사했고 마지막으로 언제 성공했나 (ADR-D012 결정 4 "평가 상태").
     * scope의 type이 ALL이면 이 기능이 다루는 자산 전체, APP·REPO면 그 앱·레포에 걸리는 자산이다
     */
    record Coverage(Hint scope, Instant lastSuccessAt) {
        public static Coverage all(Instant lastSuccessAt) {
            return new Coverage(new Hint("ALL", null, null), lastSuccessAt);
        }
    }

    /**
     * status: CONNECTED · NO_DATA · NOT_AUTHORIZED · ERROR (ADR-D011 결정 6과 같은 값).
     * acceptedCount는 점수에서 뺀 위험 수용 건수다. 수용을 다루지 않는 기능은 null
     */
    record Result(OverviewPart part, String status, List<Finding> findings, List<Coverage> coverage, Long acceptedCount) {
        public static Result failed(OverviewPart part, String status) {
            return new Result(part, status, List.of(), List.of(), null);
        }
    }
}
