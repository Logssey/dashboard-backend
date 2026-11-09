package com.logssey.reach.analyzer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON reader/writer so the tool has no dependency other than ASM. */
final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) throw p.err("trailing data");
        return v;
    }

    private IllegalArgumentException err(String m) {
        return new IllegalArgumentException("JSON " + m + " at offset " + i);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') i++;
            else break;
        }
    }

    private Object value() {
        if (i >= s.length()) throw err("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return number();
        }
    }

    private void expect(String w) {
        if (!s.startsWith(w, i)) throw err("expected " + w);
        i += w.length();
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (s.charAt(i) == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            String k = string();
            ws();
            if (s.charAt(i) != ':') throw err("expected ':'");
            i++;
            ws();
            m.put(k, value());
            ws();
            char c = s.charAt(i++);
            if (c == ',') continue;
            if (c == '}') return m;
            throw err("expected ',' or '}'");
        }
    }

    private List<Object> array() {
        List<Object> a = new ArrayList<>();
        i++;
        ws();
        if (s.charAt(i) == ']') {
            i++;
            return a;
        }
        while (true) {
            ws();
            a.add(value());
            ws();
            char c = s.charAt(i++);
            if (c == ',') continue;
            if (c == ']') return a;
            throw err("expected ',' or ']'");
        }
    }

    private String string() {
        if (s.charAt(i) != '"') throw err("expected string");
        i++;
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c != '\\') {
                b.append(c);
                continue;
            }
            char e = s.charAt(i++);
            switch (e) {
                case '"' -> b.append('"');
                case '\\' -> b.append('\\');
                case '/' -> b.append('/');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'n' -> b.append('\n');
                case 'r' -> b.append('\r');
                case 't' -> b.append('\t');
                case 'u' -> {
                    b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                }
                default -> throw err("bad escape");
            }
        }
    }

    private Object number() {
        int st = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String t = s.substring(st, i);
        if (t.isEmpty()) throw err("unexpected character '" + s.charAt(i) + "'");
        if (t.contains(".") || t.contains("e") || t.contains("E")) return Double.parseDouble(t);
        return Long.parseLong(t);
    }

    // ------------------------------------------------------------------ writer

    static String write(Object o) {
        StringBuilder b = new StringBuilder();
        write(b, o, 0);
        b.append('\n');
        return b.toString();
    }

    private static void indent(StringBuilder b, int n) {
        for (int k = 0; k < n; k++) b.append("  ");
    }

    private static boolean scalar(Object x) {
        return x == null || x instanceof String || x instanceof Number || x instanceof Boolean;
    }

    private static void write(StringBuilder b, Object o, int d) {
        if (o == null) {
            b.append("null");
        } else if (o instanceof String str) {
            quote(b, str);
        } else if (o instanceof Number || o instanceof Boolean) {
            b.append(o);
        } else if (o instanceof Map<?, ?> m) {
            if (m.isEmpty()) {
                b.append("{}");
                return;
            }
            b.append("{\n");
            int k = 0;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                indent(b, d + 1);
                quote(b, String.valueOf(e.getKey()));
                b.append(": ");
                write(b, e.getValue(), d + 1);
                if (++k < m.size()) b.append(',');
                b.append('\n');
            }
            indent(b, d);
            b.append('}');
        } else if (o instanceof Collection<?> c) {
            if (c.isEmpty()) {
                b.append("[]");
                return;
            }
            boolean simple = c.size() <= 6 && c.stream().allMatch(Json::scalar)
                    && c.stream().mapToInt(x -> String.valueOf(x).length()).sum() < 100;
            if (simple) {
                b.append('[');
                int k = 0;
                for (Object x : c) {
                    write(b, x, d);
                    if (++k < c.size()) b.append(", ");
                }
                b.append(']');
                return;
            }
            b.append("[\n");
            int k = 0;
            for (Object x : c) {
                indent(b, d + 1);
                write(b, x, d + 1);
                if (++k < c.size()) b.append(',');
                b.append('\n');
            }
            indent(b, d);
            b.append(']');
        } else {
            quote(b, o.toString());
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        b.append('"');
    }

    // ------------------------------------------------------------------ helpers for reading specs

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) {
        return o instanceof List ? (List<Object>) o : new ArrayList<>();
    }

    static String str(Object o) {
        return o == null ? null : o.toString();
    }

    static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : arr(o)) out.add(String.valueOf(x));
        return out;
    }
}
