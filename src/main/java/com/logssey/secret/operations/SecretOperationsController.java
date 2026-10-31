package com.logssey.secret.operations;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/secrets/operations")
public class SecretOperationsController {
    private final SecretOperationsService service;
    public SecretOperationsController(SecretOperationsService service){this.service=service;}
    @GetMapping("/health") public Map<String,Object> health(Authentication auth){return service.health(auth.getName());}
    @GetMapping("/alerts") public Map<String,Object> alerts(Authentication auth,@RequestParam(defaultValue="OPEN")String state,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="20")int size){return service.alerts(auth.getName(),state,page,size);}
}
