package com.logssey.secret.response;

import java.util.List;

/** General response guidance; no credential, location, or case evidence is included. */
public record SecretGuideResponse(String version, String source, String title,
                                  List<Step> steps, String notice) {
    public record Step(String code, String title, String description) {
    }
}
