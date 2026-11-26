package com.logssey.remediation;

import java.security.Principal;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/action-records")
public class ActionRecordController {
    private final ActionRecordService service;

    public ActionRecordController(ActionRecordService service) { this.service = service; }

    @GetMapping
    public ActionRecordService.Page list(Principal principal, @RequestParam(defaultValue="IAC") String area,
            @RequestParam(defaultValue="ALL") String assignee, @RequestParam(defaultValue="0") int page) {
        return service.list(name(principal),area,assignee,page);
    }

    @PostMapping("/{kind}/{id}/verification")
    public ActionRecordService.Detail link(Principal principal,@PathVariable String kind,@PathVariable long id,
            @Valid @RequestBody ActionRecordService.LinkCheck request) {
        return service.link(name(principal),kind,id,request);
    }

    @GetMapping("/{kind}/{id}")
    public ActionRecordService.Detail get(Principal principal, @PathVariable String kind, @PathVariable long id) {
        return service.get(name(principal), kind, id);
    }

    @PutMapping("/{kind}/{id}")
    public ActionRecordService.Detail save(Principal principal, @PathVariable String kind, @PathVariable long id,
                                          @Valid @RequestBody ActionRecordService.Update request) {
        return service.save(name(principal), kind, id, request);
    }

    private String name(Principal principal) { return principal == null ? null : principal.getName(); }
}
