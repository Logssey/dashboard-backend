package com.logssey.credential.scan;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** 사용자 키 형식 (커스텀 키 패턴). 로그인 + CSRF 필요. 목록·미리보기는 누구나, 등록·삭제는 관리자(ADMIN)만 */
@RestController
@RequestMapping("/api/v1/credentials/custom-patterns")
public class CustomKeyPatternController {

    private final CustomKeyPatternService service;

    public CustomKeyPatternController(CustomKeyPatternService service) {
        this.service = service;
    }

    @GetMapping
    public CustomKeyPatternService.PatternList list(Principal principal) {
        return service.list(principal.getName());
    }

    /** 저장 없이 규칙 미리보기 (폼 입력 중 실시간 표시용) */
    @PostMapping("/preview")
    public CustomKeyPatternService.PatternPreview preview(@RequestBody CustomKeyPatternService.PatternRequest request) {
        return service.preview(request);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CustomKeyPatternService.PatternItem create(Principal principal,
                                                      @RequestBody CustomKeyPatternService.PatternRequest request) {
        return service.create(principal.getName(), request);
    }

    @DeleteMapping("/{patternId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(Principal principal, @PathVariable long patternId) {
        service.delete(principal.getName(), patternId);
    }
}
