package com.logssey.help;

/** One approved usage-guide file. Only files listed in help-docs/manifest.txt become documents. */
record HelpDocument(String file, String title, String text) {

    /** The nearest "## " heading at or before the given character offset, or the document title. */
    String sectionAt(int charIndex) {
        int limit = Math.max(0, Math.min(charIndex, text.length()));
        String section = title;
        int position = 0;
        for (String line : text.split("\n", -1)) {
            if (position > limit) break;
            if (line.startsWith("## ")) section = line.substring(3).strip();
            position += line.length() + 1;
        }
        return section;
    }
}
