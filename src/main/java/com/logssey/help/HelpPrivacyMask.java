package com.logssey.help;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Replaces customer data that an administrator may paste into a question before anything leaves the server
 * (design doc 18.1): e-mail addresses, IP addresses, phone numbers, resident registration numbers and card numbers.
 * Applied to the question and to every earlier turn that is sent again. The frontend applies the same rules first.
 */
final class HelpPrivacyMask {

    static final String EMAIL = "[이메일]";
    static final String IP = "[IP]";
    static final String PHONE = "[전화번호]";
    static final String RRN = "[주민번호]";
    static final String CARD = "[카드번호]";

    private record Rule(Pattern pattern, String replacement) {
    }

    // Order matters: longer, more specific numbers first so a card number is not half-read as a phone number.
    private static final List<Rule> RULES = List.of(
            new Rule(Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"), EMAIL),
            // Digits glued to letters (hashes, tokens, digests) are left alone.
            new Rule(Pattern.compile("(?<![0-9A-Za-z])\\d{6}\\s?-\\s?[1-8]\\d{6}(?![0-9A-Za-z])"), RRN),
            new Rule(Pattern.compile("(?<![0-9A-Za-z])(?:\\d{4}[ -]?){3}\\d{4}(?![0-9A-Za-z])"), CARD),
            new Rule(Pattern.compile("(?<![0-9.])(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}"
                    + "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:/\\d{1,2})?(?![0-9.])"), IP),
            // IPv6: full form (8 groups) or compressed with "::". Times such as 10:30:00 are left alone.
            new Rule(Pattern.compile("(?i)(?<![0-9a-z:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
                    + "|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?)(?![0-9a-z:])"), IP),
            new Rule(Pattern.compile("(?<![0-9A-Za-z])(?:\\+82[ -]?1\\d|0\\d{1,2})[ .-]?\\d{3,4}[ .-]?\\d{4}(?![0-9A-Za-z])"), PHONE));

    private HelpPrivacyMask() {
    }

    static String mask(String text) {
        if (text == null || text.isEmpty()) return text;
        String result = text;
        for (Rule rule : RULES) result = rule.pattern().matcher(result).replaceAll(rule.replacement());
        return result;
    }

    static boolean changes(String text) {
        return text != null && !text.equals(mask(text));
    }
}
