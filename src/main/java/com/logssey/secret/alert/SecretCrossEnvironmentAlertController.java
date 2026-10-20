package com.logssey.secret.alert;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/v1/secrets/cross-environment-alerts")
public class SecretCrossEnvironmentAlertController {
 private final SecretCrossEnvironmentAlertService service;public SecretCrossEnvironmentAlertController(SecretCrossEnvironmentAlertService service){this.service=service;}
 @GetMapping public Map<String,Object> list(@RequestParam(defaultValue="OPEN")String status,@RequestParam(defaultValue="ALL")String owner,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="20")int size,Authentication a){return service.list(login(a),status,owner,page,size);}
 @GetMapping("/{alertId}") public Map<String,Object> detail(@PathVariable long alertId,Authentication a){return service.detail(login(a),alertId);}
 @PatchMapping("/{alertId}/assignment") public Map<String,Object> assign(@PathVariable long alertId,@RequestBody SecretCrossEnvironmentAlertRequests.Assignment r,Authentication a){return service.assign(login(a),alertId,r);}
 @PostMapping("/{alertId}/acknowledge") public Map<String,Object> ack(@PathVariable long alertId,@RequestBody SecretCrossEnvironmentAlertRequests.Acknowledge r,Authentication a){return service.acknowledge(login(a),alertId,r);}
 @PostMapping("/{alertId}/close") public Map<String,Object> close(@PathVariable long alertId,@RequestBody SecretCrossEnvironmentAlertRequests.Close r,Authentication a){return service.close(login(a),alertId,r);}
 private static String login(Authentication a){return a==null?null:a.getName();}
}
