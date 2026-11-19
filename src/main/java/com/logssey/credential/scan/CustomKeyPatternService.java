package com.logssey.credential.scan;

import java.util.Arrays;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Service;

/**
 * 사용자 키 형식 등록·목록·삭제·미리보기.
 * 폼 입력 → KeyRuleCompiler로 검사·정규식 생성 → DB 저장. 다음 스캔부터 스캐너가 같이 검사한다.
 */
@Service
public class CustomKeyPatternService {

    /** 스캔 비용을 묶어 두기 위한 등록 한도 */
    static final int MAX_PATTERNS = 50;
    /** 미리보기에 붙여 넣을 수 있는 샘플 글 길이 */
    static final int MAX_SAMPLE = 10_000;

    public record PatternRequest(String name, String prefix, KeyCharset charset, Integer length, Boolean secret,
                                 String sample) {
    }

    public record PatternItem(long id, String name, String prefix, KeyCharset charset, String charsetLabel,
                              int length, boolean secret, String rule, String createdBy, String createdAt) {
    }

    public record CharsetOption(KeyCharset code, String label) {
    }

    /** @param canManage 지금 사용자가 등록·삭제할 수 있는지 (관리자만). 화면이 폼을 잠글 때 쓴다 */
    public record PatternList(List<PatternItem> items, List<CharsetOption> charsets, int limit, boolean canManage) {
    }

    /** 미리보기 결과. 샘플에서 찾은 값은 마스킹해서만 돌려준다 */
    public record PatternPreview(String rule, String example, List<String> sampleMatches) {
    }

    private final CustomKeyPatternRepository repository;

    public CustomKeyPatternService(CustomKeyPatternRepository repository) {
        this.repository = repository;
    }

    /** 목록 보기는 로그인한 누구나. 등록·삭제 가능 여부를 함께 알려 준다 */
    public PatternList list(String actor) {
        List<CharsetOption> charsets = Arrays.stream(KeyCharset.values())
                .map(c -> new CharsetOption(c, c.label()))
                .toList();
        return new PatternList(repository.findAll().stream().map(CustomKeyPatternService::toItem).toList(),
                charsets, MAX_PATTERNS, isAdmin(actor));
    }

    /** 저장하지 않고 규칙만 만들어 본다. 샘플 글은 저장·로그하지 않는다 */
    public PatternPreview preview(PatternRequest request) {
        CustomKeyRule rule = build(request);
        List<String> matches = List.of();
        if (request.sample() != null && !request.sample().isEmpty()) {
            if (request.sample().length() > MAX_SAMPLE) {
                throw new ApiException(ErrorCode.INVALID_INPUT, "샘플은 %d자 이하로 넣어 주세요.".formatted(MAX_SAMPLE));
            }
            matches = SecretScanner.scan(request.sample(), List.of(rule)).stream()
                    .filter(m -> m.pattern() == rule)
                    .map(SecretMatch::masked)
                    .toList();
        }
        return new PatternPreview(
                KeyRuleCompiler.readable(rule.prefix(), rule.charset(), rule.length()),
                KeyRuleCompiler.example(rule.prefix(), rule.charset(), rule.length()),
                matches);
    }

    /** 탐지 결과를 바꾸는 작업이라 관리자만 할 수 있다 */
    public PatternItem create(String actor, PatternRequest request) {
        requireAdmin(actor);
        CustomKeyRule rule = build(request);
        if (repository.count() >= MAX_PATTERNS) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "키 형식은 최대 %d개까지 등록할 수 있어요.".formatted(MAX_PATTERNS));
        }
        if (repository.exists(rule.prefix(), rule.charset(), rule.length())) {
            throw new ApiException(ErrorCode.CONFLICT, "같은 접두사·문자 종류·길이의 형식이 이미 있어요.");
        }
        return toItem(repository.insert(rule.name(), rule.prefix(), rule.charset(), rule.length(), rule.secret(), actor));
    }

    public void delete(String actor, long id) {
        requireAdmin(actor);
        if (!repository.delete(id)) {
            throw new ApiException(ErrorCode.NOT_FOUND, "등록된 키 형식을 찾을 수 없어요.");
        }
    }

    private boolean isAdmin(String actor) {
        return actor != null && !actor.isBlank() && repository.isAdmin(actor);
    }

    private void requireAdmin(String actor) {
        if (actor == null || actor.isBlank()) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        if (!repository.isAdmin(actor)) {
            throw new ApiException(ErrorCode.FORBIDDEN, "키 형식 등록·삭제는 관리자만 할 수 있어요.");
        }
    }

    private static CustomKeyRule build(PatternRequest request) {
        if (request == null) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        try {
            return KeyRuleCompiler.build(0, request.name(), request.prefix(), request.charset(),
                    request.length() == null ? -1 : request.length(),
                    request.secret() == null || request.secret());
        } catch (InvalidKeyRuleException e) {
            throw new ApiException(ErrorCode.INVALID_INPUT, e.getMessage());
        }
    }

    private static PatternItem toItem(CustomKeyPatternRepository.StoredPattern p) {
        return new PatternItem(p.id(), p.name(), p.prefix(), p.charset(), p.charset().label(), p.length(), p.secret(),
                KeyRuleCompiler.readable(p.prefix(), p.charset(), p.length()), p.createdBy(),
                p.createdAt().toString());
    }
}
