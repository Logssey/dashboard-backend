package com.logssey.reach.analyzer;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.jar.JarFile;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Compares the methods of two releases of a library jar. It is the first step of making verdict data for a new CVE
 * (vulndata/vulndata.py): the methods a fix changed are the candidates for the vulnerable functions.
 *
 * <pre>
 * java -cp reach-analyzer.jar com.logssey.reach.analyzer.MethodDiff old.jar new.jar
 *     status \t class \t method \t desc \t lines      status = CHANGED | REMOVED | ADDED
 * java -cp reach-analyzer.jar com.logssey.reach.analyzer.MethodDiff --list one.jar
 *     class \t method \t desc \t lines
 * </pre>
 *
 * lines are the source lines of the method as ranges ("611-640,655"), from the old jar for CHANGED and REMOVED,
 * or "-" when the jar has no line numbers. A method counts as changed when its instructions differ. Line numbers,
 * local variable names and stack frames are left out, and operands are compared by name, so a release that was
 * only recompiled or whose constant pool was reordered shows no change.
 */
public final class MethodDiff {

    private MethodDiff() {}

    public static void main(String[] args) throws IOException {
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
        if (args.length == 2 && args[0].equals("--list")) {
            Map<String, String> lines = lines(args[1]);
            for (String key : new TreeSet<>(fingerprints(args[1]).keySet())) {
                out.println(key + "\t" + lines.getOrDefault(key, "-"));
            }
        } else if (args.length == 2) {
            Map<String, String> before = fingerprints(args[0]);
            Map<String, String> after = fingerprints(args[1]);
            Map<String, String> beforeLines = lines(args[0]);
            Map<String, String> afterLines = lines(args[1]);
            var keys = new TreeSet<String>(before.keySet());
            keys.addAll(after.keySet());
            for (String key : keys) {
                String x = before.get(key);
                String y = after.get(key);
                if (x != null && x.equals(y)) continue;
                String status = x == null ? "ADDED" : y == null ? "REMOVED" : "CHANGED";
                String where = (x == null ? afterLines : beforeLines).getOrDefault(key, "-");
                out.println(status + "\t" + key + "\t" + where);
            }
        } else {
            System.err.println("usage: MethodDiff <old.jar> <new.jar> | MethodDiff --list <jar>");
            System.exit(2);
        }
        out.flush();
    }

    /** class \t method \t desc -> fingerprint of the instructions */
    static Map<String, String> fingerprints(String jar) throws IOException {
        var out = new HashMap<String, String>();
        read(jar, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES, (cls, name, desc, access) -> {
            var text = new StringBuilder().append(access).append(';');
            return new Recorder(text, () -> out.put(cls + "\t" + name + "\t" + desc, sha(text.toString())));
        });
        return out;
    }

    /** class \t method \t desc -> source lines as ranges. Methods without line numbers are left out */
    static Map<String, String> lines(String jar) throws IOException {
        var out = new TreeMap<String, String>();
        read(jar, ClassReader.SKIP_FRAMES, (cls, name, desc, access) -> {
            var seen = new TreeSet<Integer>();
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitLineNumber(int line, Label start) {
                    seen.add(line);
                }

                @Override
                public void visitEnd() {
                    if (!seen.isEmpty()) out.put(cls + "\t" + name + "\t" + desc, ranges(seen));
                }
            };
        });
        return out;
    }

    static String ranges(TreeSet<Integer> lines) {
        var out = new StringBuilder();
        int start = -1;
        int last = -1;
        for (int line : lines) {
            if (start < 0) {
                start = line;
            } else if (line != last + 1) {
                append(out, start, last);
                start = line;
            }
            last = line;
        }
        if (start >= 0) append(out, start, last);
        return out.toString();
    }

    private static void append(StringBuilder out, int start, int last) {
        if (out.length() > 0) out.append(',');
        out.append(start);
        if (last != start) out.append('-').append(last);
    }

    private interface MethodHandler {
        MethodVisitor visit(String cls, String name, String desc, int access);
    }

    /** Classes of the base release only: META-INF/versions/* (multi-release) and module-info are skipped */
    private static void read(String jar, int flags, MethodHandler handler) throws IOException {
        try (var file = new JarFile(jar)) {
            for (var entry : Collections.list(file.entries())) {
                String name = entry.getName();
                if (!name.endsWith(".class") || name.startsWith("META-INF/") || name.endsWith("module-info.class")) {
                    continue;
                }
                try (InputStream in = file.getInputStream(entry)) {
                    new ClassReader(in).accept(new ClassVisitor(Opcodes.ASM9) {
                        private String cls;

                        @Override
                        public void visit(int version, int access, String internalName, String signature,
                                          String superName, String[] interfaces) {
                            cls = internalName.replace('/', '.');
                        }

                        @Override
                        public MethodVisitor visitMethod(int access, String method, String desc, String signature,
                                                         String[] exceptions) {
                            return handler.visit(cls, method, desc, access);
                        }
                    }, flags);
                }
            }
        }
    }

    private static String sha(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes the instructions of one method as text. Labels are numbered in order of first use */
    private static final class Recorder extends MethodVisitor {
        private final StringBuilder text;
        private final Runnable done;
        private final Map<Label, Integer> ids = new HashMap<>();

        Recorder(StringBuilder text, Runnable done) {
            super(Opcodes.ASM9);
            this.text = text;
            this.done = done;
        }

        private int id(Label label) {
            return ids.computeIfAbsent(label, key -> ids.size());
        }

        private void write(Object... parts) {
            for (Object part : parts) text.append(part).append(' ');
            text.append('\n');
        }

        private String ids(Label... labels) {
            var out = new StringBuilder();
            for (Label label : labels) out.append(id(label)).append(',');
            return out.toString();
        }

        @Override
        public void visitInsn(int opcode) {
            write(opcode);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            write(opcode, operand);
        }

        @Override
        public void visitVarInsn(int opcode, int index) {
            write(opcode, index);
        }

        @Override
        public void visitTypeInsn(int opcode, String type) {
            write(opcode, type);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {
            write(opcode, owner, name, desc);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean isInterface) {
            write(opcode, owner, name, desc);
        }

        @Override
        public void visitInvokeDynamicInsn(String name, String desc, Handle bootstrap, Object... arguments) {
            write("indy", name, desc, bootstrap, Arrays.deepToString(arguments));
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            write(opcode, "L" + id(label));
        }

        @Override
        public void visitLabel(Label label) {
            write("L" + id(label) + ":");
        }

        @Override
        public void visitLdcInsn(Object value) {
            write("ldc", value);
        }

        @Override
        public void visitIincInsn(int index, int increment) {
            write("iinc", index, increment);
        }

        @Override
        public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
            write("tswitch", min, max, id(dflt), ids(labels));
        }

        @Override
        public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            write("lswitch", id(dflt), Arrays.toString(keys), ids(labels));
        }

        @Override
        public void visitMultiANewArrayInsn(String desc, int dimensions) {
            write("multi", desc, dimensions);
        }

        @Override
        public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
            write("try", id(start), id(end), id(handler), type);
        }

        @Override
        public void visitEnd() {
            done.run();
        }
    }
}
