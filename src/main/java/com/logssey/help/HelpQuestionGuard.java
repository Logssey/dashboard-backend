package com.logssey.help;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects values that look like credentials so they are never sent to the model provider.
 * False positives are acceptable: the user is asked to remove the value and ask again.
 */
final class HelpQuestionGuard {

    private static final Pattern KNOWN_FORMATS = Pattern.compile(
            "sk-ant-[A-Za-z0-9_-]{8,}"
                    + "|\\bgh[pousr]_[A-Za-z0-9]{20,}"
                    + "|github_pat_[A-Za-z0-9_]{20,}"
                    + "|\\b(?:ntn|secret)_[A-Za-z0-9]{20,}"
                    + "|\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"
                    + "|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                    + "|\\bxox[abposr]-[A-Za-z0-9-]{10,}"
                    + "|\\bAIza[0-9A-Za-z_-]{35}"
                    + "|\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.");
    private static final Pattern LONG_TOKEN = Pattern.compile("[A-Za-z0-9+/_=-]{32,}");
    private static final double ENTROPY_THRESHOLD = 3.5;

    private HelpQuestionGuard() {
    }

    static boolean containsSecretLikeValue(String text) {
        if (text == null || text.isEmpty()) return false;
        if (KNOWN_FORMATS.matcher(text).find()) return true;
        Matcher matcher = LONG_TOKEN.matcher(text);
        while (matcher.find()) {
            String token = matcher.group();
            boolean hasDigit = token.chars().anyMatch(Character::isDigit);
            boolean hasLetter = token.chars().anyMatch(Character::isLetter);
            if (hasDigit && hasLetter && entropy(token) >= ENTROPY_THRESHOLD) return true;
        }
        return false;
    }

    private static double entropy(String value) {
        var counts = new HashMap<Character, Integer>();
        for (char c : value.toCharArray()) counts.merge(c, 1, Integer::sum);
        double result = 0;
        for (int count : counts.values()) {
            double p = (double) count / value.length();
            result -= p * (Math.log(p) / Math.log(2));
        }
        return result;
    }
}
