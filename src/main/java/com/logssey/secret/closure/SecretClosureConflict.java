package com.logssey.secret.closure;

import java.util.List;
import com.logssey.common.error.*;
import static com.logssey.secret.closure.SecretClosureContracts.*;

public final class SecretClosureConflict extends ApiException {
    private final List<Check> checks;
    public SecretClosureConflict(List<Check> checks) {
        super(ErrorCode.CONFLICT,"해결 근거를 다시 확인해 주세요.");this.checks=List.copyOf(checks);
    }
    public List<Check> checks() {return checks;}
}
