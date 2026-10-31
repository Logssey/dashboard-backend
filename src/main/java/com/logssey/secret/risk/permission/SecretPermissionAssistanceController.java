package com.logssey.secret.risk.permission;
import java.security.Principal;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/secrets/occurrences/{occurrence}/permission-assistance")
public class SecretPermissionAssistanceController {
    private final SecretPermissionAssistanceService service;
    public SecretPermissionAssistanceController(SecretPermissionAssistanceService service){this.service=service;}
    @GetMapping public Map<String,Object> context(@PathVariable long occurrence,Principal actor){return service.context(actor.getName(),occurrence);}
    @PostMapping("/requests") @ResponseStatus(HttpStatus.ACCEPTED) public Map<String,Object> request(@PathVariable long occurrence,@RequestBody SecretPermissionAssistanceService.Request body,Principal actor){return service.request(actor.getName(),occurrence,body);}
    @GetMapping("/requests/{id}")public Map<String,Object> status(@PathVariable long occurrence,@PathVariable long id,Principal actor){return service.status(actor.getName(),occurrence,id);}
    @GetMapping("/observations/{id}/preview")public Map<String,Object> preview(@PathVariable long occurrence,@PathVariable long id,Principal actor){return service.preview(actor.getName(),occurrence,id);}
    @PostMapping("/observations/{id}/confirm")public Map<String,Object> confirm(@PathVariable long occurrence,@PathVariable long id,@RequestBody SecretPermissionAssistanceService.Confirm body,Principal actor){return service.confirm(actor.getName(),occurrence,id,body);}
    @PostMapping("/observations/{id}/reject")public Map<String,Object> reject(@PathVariable long occurrence,@PathVariable long id,@RequestBody SecretPermissionAssistanceService.Reject body,Principal actor){return service.reject(actor.getName(),occurrence,id,body);}
}
