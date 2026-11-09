package com.logssey.reach.analyzer;

import java.util.LinkedHashMap;
import java.util.Map;

/** An annotation occurrence with its (simplified) element values. */
final class Ann {
    final String desc;
    final Map<String, Object> values = new LinkedHashMap<>();

    Ann(String desc) {
        this.desc = desc;
    }
}
