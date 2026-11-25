package com.logssey.help;

import java.security.SecureRandom;

/** Random, never-real credential-shaped strings for tests. */
final class HelpTestKeys {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private HelpTestKeys() {
    }

    static String random(String alphabet, int length) {
        var builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) builder.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        return builder.toString();
    }

    static String anthropicLike() { return "sk-ant-" + random(ALNUM, 40); }
    static String githubLike() { return "ghp_" + random(ALNUM, 36); }
    static String awsAccessKeyLike() { return "AKIA" + random(UPPER, 16); }
    static String opaqueToken() { return random(ALNUM, 48); }
}
