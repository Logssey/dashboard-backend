package com.logssey.secret.query;

import java.util.Locale;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.connection.SecretDisplayLabels;

/** Search only public projections after occurrence authorization; never index collected values. */
public final class SecretSafeSearch {
    private SecretSafeSearch() { }
    public static String normalize(String q) {
        if (q == null || q.isBlank()) return null;
        String value = q.strip();
        if (value.length() > 100 || value.codePoints().anyMatch(Character::isISOControl)
                || SecretDisplayLabels.credentialLike(value)) throw new ApiException(ErrorCode.INVALID_INPUT);
        return value;
    }
    public static boolean matches(String q, Object... publicFields) {
        if (q == null) return true;
        String needle = q.toLowerCase(Locale.ROOT);
        for (Object field : publicFields) {
            if (field instanceof String text && text.toLowerCase(Locale.ROOT).contains(needle)) return true;
        }
        return false;
    }
}
