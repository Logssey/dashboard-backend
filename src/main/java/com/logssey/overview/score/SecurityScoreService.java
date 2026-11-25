package com.logssey.overview.score;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

/**
 * 보안 점수 (dashboard-design-docs ADR-D012). 등록된 {@link ScoreSource}를 모두 읽어 {@link SecurityScoreCalculator}로 계산한다.
 * 한 기능을 읽다가 실패해도 나머지로 계산한다(그 기능은 ERROR이고, 그 기능만 평가하던 자산은 평가 안 됨이 된다)
 */
@Service
public class SecurityScoreService {

    private static final Logger log = LoggerFactory.getLogger(SecurityScoreService.class);

    private final List<ScoreSource> sources;
    private final JdbcClient jdbc;
    private final ScoreAssets assets = ScoreAssets.load();

    public SecurityScoreService(List<ScoreSource> sources, JdbcClient jdbc) {
        this.sources = sources.stream().sorted(Comparator.comparing(ScoreSource::part)).toList();
        this.jdbc = jdbc;
    }

    public SecurityScoreResponse score(String login) {
        if (login == null) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        List<ScoreSource.Result> results = new ArrayList<>();
        for (var source : sources) results.add(read(source, login));
        return SecurityScoreCalculator.calculate(assets, dataAssetArns(), results, Instant.now());
    }

    private static ScoreSource.Result read(ScoreSource source, String login) {
        try {
            return source.read(login);
        } catch (ApiException e) {
            if (e.errorCode() == ErrorCode.FORBIDDEN) return ScoreSource.Result.failed(source.part(), "NOT_AUTHORIZED");
            log.warn("security score: {} read failed: {}", source.part(), e.errorCode());
            return ScoreSource.Result.failed(source.part(), "ERROR");
        } catch (RuntimeException e) {
            log.warn("security score: {} read failed", source.part(), e);
            return ScoreSource.Result.failed(source.part(), "ERROR");
        }
    }

    /** IaC 데이터 자산 등급표의 ARN → kind. 데이터 자산을 ARN으로 찾을 때 쓴다 */
    private Map<String, String> dataAssetArns() {
        Map<String, String> arns = new HashMap<>();
        jdbc.sql("SELECT arn, kind FROM iac_data_assets")
                .query((rs, n) -> arns.put(rs.getString("arn"), rs.getString("kind"))).list();
        return arns;
    }
}
