package com.logssey.help;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.logssey.common.error.ApiErrorResponse;
import com.logssey.help.HelpChatDtos.ChatRequest;
import com.logssey.help.HelpChatDtos.ChatResponse;
import com.logssey.help.HelpChatDtos.ReportRequest;
import com.logssey.help.HelpChatDtos.ReportResponse;
import com.logssey.help.HelpChatDtos.StatusResponse;
import com.logssey.help.HelpChatService.HelpChatException;

/** Usage-help chatbot API. Login and CSRF are enforced by the shared SecurityConfig. */
@RestController
@RequestMapping("/api/v1/help")
class HelpChatController {

    private final HelpChatService service;

    HelpChatController(HelpChatService service) {
        this.service = service;
    }

    @GetMapping("/status")
    StatusResponse status() {
        return service.status();
    }

    @PostMapping("/chat")
    ChatResponse chat(Principal principal, @RequestBody ChatRequest request) {
        return service.chat(principal.getName(), request);
    }

    @PostMapping("/report")
    ReportResponse report(Principal principal, @RequestBody ReportRequest request) {
        return service.report(principal.getName(), request);
    }

    @ExceptionHandler(HelpChatException.class)
    ResponseEntity<ApiErrorResponse> handle(HelpChatException e) {
        var builder = ResponseEntity.status(status(e.code()));
        if (e.retryAfterSeconds() > 0) builder.header("Retry-After", Integer.toString(e.retryAfterSeconds()));
        return builder.body(new ApiErrorResponse(e.code(), message(e)));
    }

    static HttpStatus status(String code) {
        return switch (code) {
            case "INVALID_INPUT", "MEMO_INVALID", "QUESTION_REJECTED" -> HttpStatus.BAD_REQUEST;
            case "RATE_LIMITED", "DAILY_LIMIT", "BUSY" -> HttpStatus.TOO_MANY_REQUESTS;
            case "NOT_CONFIGURED" -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.BAD_GATEWAY;
        };
    }

    static String message(HelpChatException e) {
        return switch (e.code()) {
            case "INVALID_INPUT" -> "질문은 1~500자로 입력해 주세요.";
            case "MEMO_INVALID" -> "조치 메모는 1~1500자로 입력해 주세요.";
            case "REPORT_BLOCKED" -> "초안을 만들지 못했어요. 메모를 조금 고쳐 다시 시도해 주세요.";
            case "QUESTION_REJECTED" -> "키나 토큰처럼 보이는 값이 있어 보내지 않았어요. 값을 지우고 다시 물어봐 주세요.";
            case "RATE_LIMITED" -> "질문이 너무 잦아요. " + Math.max(1, e.retryAfterSeconds()) + "초 뒤에 다시 물어봐 주세요.";
            case "DAILY_LIMIT" -> "오늘 질문 한도를 모두 썼어요. 내일 다시 이용해 주세요.";
            case "BUSY" -> "이전 질문에 답하는 중이에요. 잠시 후 다시 보내 주세요.";
            case "NOT_CONFIGURED" -> "도움말 챗봇이 아직 준비되지 않았어요.";
            default -> "답변을 받지 못했어요. 잠시 후 다시 시도해 주세요.";
        };
    }
}
