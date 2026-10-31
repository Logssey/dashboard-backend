package com.logssey.secret.operations;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretRole;
import java.time.Duration;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import static com.logssey.secret.operations.SecretOperationsHealth.facts;

@Service
public class SecretOperationsService {
    private final SecretOperationsStore store;
    private final SecretAccessService access;
    @org.springframework.beans.factory.annotation.Autowired
    public SecretOperationsService(JdbcTemplate jdbc,PlatformTransactionManager manager,SecretAccessService access,
            @Value("${logssey.secret.operations.heartbeat-grace:2m}") Duration grace,
            @Value("${logssey.secret.operations.queue-grace:2m}") Duration queueGrace,
            @Value("${logssey.secret.operations.expected-instances:1}") int expected,
            @Value("${logssey.secret.operations.deployment-key:secret-worker}") String deployment){
        this.store=new SecretOperationsStore(jdbc,manager,grace,queueGrace,expected,deployment);this.access=access;
    }
    public SecretOperationsService(JdbcTemplate jdbc,PlatformTransactionManager manager,SecretAccessService access,Duration grace,Duration queueGrace,int expected){
        this(jdbc,manager,access,grace,queueGrace,expected,"secret-worker");
    }
    private void authorize(String login){var actor=access.requirePrincipal(login);if(!access.hasGlobalRole(actor,SecretRole.SECURITY)&&!access.hasGlobalRole(actor,SecretRole.OPERATIONS))throw new ApiException(ErrorCode.FORBIDDEN);}
    void monitor(){store.monitor();}
    public Map<String,Object> health(String login){
        try{authorize(login);return store.health();}
        catch(DataAccessException failure){return facts("status","UNAVAILABLE","asOf",null,"components",List.of(),"queue",null,"alerts",null,"maintenance",null,"reasonCode","DATABASE_UNAVAILABLE");}
    }
    public Map<String,Object> alerts(String login,String state,int page,int size){
        if(!Set.of("OPEN","RECOVERED","ALL").contains(state)||page<0||page>100000||size<1||size>100)throw new ApiException(ErrorCode.INVALID_INPUT);
        try{authorize(login);return store.alerts(state,page,size);}
        catch(DataAccessException failure){return facts("status","UNAVAILABLE","items",List.of(),"total",null,"page",page,"size",size,"reasonCode","DATABASE_UNAVAILABLE");}
    }
}
