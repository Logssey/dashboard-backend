package com.logssey.secret.response;

import java.util.List;

public record SecretTriageCandidateList(List<SecretTriageCandidate> items, Long total,
                                        Integer page, Integer size) {
}
