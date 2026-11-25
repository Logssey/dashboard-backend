package com.logssey.secret.evidence;

import java.util.Map;
import com.logssey.common.error.*;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.investigation.SecretInvestigationService;
import com.logssey.secret.policy.SecretStoragePolicyService;
import com.logssey.secret.response.SecretLocationWorkflow;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets/internal-records")
public class SecretInternalRecordController {
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretLocationWorkflow cases;
    private final SecretStoragePolicyService policies;
    private final SecretInvestigationService investigations;

    public SecretInternalRecordController(JdbcTemplate jdbc, SecretAccessService access,
            SecretLocationWorkflow cases, SecretStoragePolicyService policies, SecretInvestigationService investigations) {
        this.jdbc=jdbc; this.access=access; this.cases=cases; this.policies=policies; this.investigations=investigations;
    }

    @GetMapping("/{id}")
    public Map<String,Object> detail(@PathVariable long id, Authentication authentication) {
        String login=authentication==null?null:authentication.getName();
        var actor=access.requirePrincipal(login);
        var rows=jdbc.queryForList("SELECT r.*,u.display_name FROM secret_internal_records r JOIN dashboard_users u ON u.user_id=r.actor_user_id WHERE record_id=?",id);
        if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        var r=rows.getFirst(); long target=((Number)r.get("target_id")).longValue(), version=((Number)r.get("target_version")).longValue();
        // Reuse the target's live authorization, including revoked grants and partial case visibility.
        switch(r.get("target_type").toString()) {
            case "OCCURRENCE" -> access.requireOccurrenceRead(actor,target);
            case "SCOPE" -> policies.classification(target,login);
            case "POLICY" -> policies.policy(target,version,login);
            case "INVESTIGATION" -> investigations.detail(login,target);
            case "CASE" -> {
                cases.detail(target,login);
                if(!cases.hasAllSecurity(actor,target) && ((Number)r.get("actor_user_id")).longValue()!=actor.userId())
                    throw new ApiException(ErrorCode.NOT_FOUND);
            }
            default -> throw new ApiException(ErrorCode.NOT_FOUND);
        }
        return Map.of("recordId",id,"targetType",r.get("target_type"),"targetId",target,"targetVersion",version,
            "eventCode",r.get("event_code"),"actorDisplayName",r.get("display_name"),"createdAt",r.get("created_at"));
    }
}
