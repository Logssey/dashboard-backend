package org.springframework.util;

/** Fixture stub: same signatures as spring-core's StringUtils methods used by spring-security-crypto. */
public abstract class StringUtils {
    public static boolean hasLength(CharSequence str) {
        return (str != null && str.length() > 0);
    }

    public static boolean hasLength(String str) {
        return (str != null && !str.isEmpty());
    }
}
