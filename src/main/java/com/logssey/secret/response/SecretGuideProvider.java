package com.logssey.secret.response;

import java.util.List;
import java.util.Optional;

/** A provider selects only catalog codes; all displayed wording remains server-authored. */
interface SecretGuideProvider {
    Optional<List<String>> selectSteps(SecretGuideContext context);
}
