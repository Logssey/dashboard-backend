package com.logssey.reach.analyzer;

import org.objectweb.asm.ClassReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * All classes of the analysed application: first-party classes ("app") and bundled libraries.
 * Supports a Spring Boot fat jar (BOOT-INF/classes + BOOT-INF/lib), a WAR layout, an extracted
 * directory of either, or a plain classes directory/jar plus extra --lib entries.
 */
final class ClassIndex {
    final Map<String, ClassInfo> classes = new HashMap<>();
    final Map<String, Integer> jarClassCount = new LinkedHashMap<>();
    final List<String> warnings = new ArrayList<>();
    int appClasses;
    int libClasses;
    int duplicates;
    private final JdkTypes jdk = new JdkTypes();

    ClassInfo get(String internalName) {
        return classes.get(internalName);
    }

    /** Class header from the index, or from the running JDK (header only) for java.* etc. */
    ClassInfo info(String internalName) {
        ClassInfo ci = classes.get(internalName);
        return ci != null ? ci : jdk.get(internalName);
    }

    boolean isJdk(String internalName) {
        return classes.get(internalName) == null && jdk.get(internalName) != null;
    }

    void add(byte[] bytes, String origin, boolean app) {
        ClassReader cr;
        try {
            cr = new ClassReader(bytes);
        } catch (RuntimeException e) {
            warnings.add("unreadable class in " + origin + ": " + e.getMessage());
            return;
        }
        String name = cr.getClassName();
        if (name.equals("module-info") || name.endsWith("/package-info")) return;
        if (classes.containsKey(name)) {
            duplicates++;
            return;
        }
        ClassInfo ci = new ClassInfo(name, origin, app, bytes);
        try {
            cr.accept(new HeaderVisitor(ci), ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (RuntimeException e) {
            warnings.add("cannot parse " + name + " in " + origin + ": " + e);
            return;
        }
        classes.put(name, ci);
        if (app) appClasses++;
        else {
            libClasses++;
            jarClassCount.merge(origin, 1, Integer::sum);
        }
    }

    // ------------------------------------------------------------------ loading

    void load(Path app, List<Path> libs) throws IOException {
        if (Files.isDirectory(app)) {
            if (Files.isDirectory(app.resolve("BOOT-INF/classes"))) {
                loadClassDir(app.resolve("BOOT-INF/classes"));
                loadJarDir(app.resolve("BOOT-INF/lib"));
            } else if (Files.isDirectory(app.resolve("WEB-INF/classes"))) {
                loadClassDir(app.resolve("WEB-INF/classes"));
                loadJarDir(app.resolve("WEB-INF/lib"));
            } else {
                loadClassDir(app);
            }
        } else {
            loadArchive(app);
        }
        for (Path l : libs) {
            if (Files.isDirectory(l)) loadJarDir(l);
            else loadJarFile(l);
        }
    }

    private void loadArchive(Path archive) throws IOException {
        try (ZipFile zf = new ZipFile(archive.toFile())) {
            boolean boot = false;
            boolean war = false;
            for (Enumeration<? extends ZipEntry> en = zf.entries(); en.hasMoreElements(); ) {
                String n = en.nextElement().getName();
                if (n.startsWith("BOOT-INF/classes/")) boot = true;
                if (n.startsWith("WEB-INF/classes/")) war = true;
            }
            String classPrefix = boot ? "BOOT-INF/classes/" : war ? "WEB-INF/classes/" : "";
            String libPrefix = boot ? "BOOT-INF/lib/" : war ? "WEB-INF/lib/" : null;
            for (Enumeration<? extends ZipEntry> en = zf.entries(); en.hasMoreElements(); ) {
                ZipEntry e = en.nextElement();
                String n = e.getName();
                if (e.isDirectory()) continue;
                if (libPrefix != null && n.startsWith(libPrefix) && n.endsWith(".jar")) {
                    try (InputStream in = zf.getInputStream(e)) {
                        loadJarStream(in, n.substring(libPrefix.length()));
                    }
                } else if (n.endsWith(".class") && n.startsWith(classPrefix)) {
                    String rel = n.substring(classPrefix.length());
                    if (classPrefix.isEmpty() && (rel.startsWith("META-INF/") || rel.startsWith("org/springframework/boot/loader/"))) {
                        continue;
                    }
                    try (InputStream in = zf.getInputStream(e)) {
                        add(in.readAllBytes(), "app", true);
                    }
                }
            }
        }
    }

    private void loadClassDir(Path dir) throws IOException {
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                if (Files.isRegularFile(p) && p.toString().endsWith(".class")) {
                    String rel = dir.relativize(p).toString().replace('\\', '/');
                    if (rel.startsWith("META-INF/")) continue;
                    add(Files.readAllBytes(p), "app", true);
                }
            }
        }
    }

    private void loadJarDir(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) return;
        List<Path> jars = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.jar")) {
            for (Path p : ds) jars.add(p);
        }
        jars.sort(null);
        for (Path p : jars) loadJarFile(p);
    }

    private void loadJarFile(Path jar) throws IOException {
        try (InputStream in = Files.newInputStream(jar)) {
            loadJarStream(in, jar.getFileName().toString());
        }
    }

    private void loadJarStream(InputStream raw, String jarName) throws IOException {
        jarClassCount.putIfAbsent(jarName, 0);
        byte[] jarBytes = readAll(raw);
        try (ZipInputStream zin = new ZipInputStream(new java.io.ByteArrayInputStream(jarBytes))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                String n = e.getName();
                if (e.isDirectory() || !n.endsWith(".class") || n.startsWith("META-INF/")) continue;
                add(readAll(zin), jarName, false);
            }
        } catch (java.util.zip.ZipException ze) {
            // some jars (STORED entries with data descriptors) cannot be streamed: fall back to a temp file
            Path tmp = Files.createTempFile("reach-", ".jar");
            try {
                Files.write(tmp, jarBytes);
                try (ZipFile zf = new ZipFile(tmp.toFile())) {
                    for (Enumeration<? extends ZipEntry> en = zf.entries(); en.hasMoreElements(); ) {
                        ZipEntry e = en.nextElement();
                        String n = e.getName();
                        if (e.isDirectory() || !n.endsWith(".class") || n.startsWith("META-INF/")) continue;
                        try (InputStream in = zf.getInputStream(e)) {
                            byte[] b = in.readAllBytes();
                            add(b, jarName, false); // classes already read before the failure are ignored as duplicates
                        }
                    }
                }
                warnings.add("read " + jarName + " via temp file (" + ze.getMessage() + ")");
            } finally {
                Files.deleteIfExists(tmp);
            }
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        byte[] buf = new byte[8192];
        int r;
        while ((r = in.read(buf)) > 0) out.write(buf, 0, r);
        return out.toByteArray();
    }

    // ------------------------------------------------------------------ JDK class headers

    /** Reads JDK class headers (java.*, javax.*, jdk.*) from the running JVM's jrt:/ image. */
    static final class JdkTypes {
        private final FileSystem jrt;
        private final Map<String, ClassInfo> cache = new HashMap<>();
        private final Set<String> missing = new HashSet<>();

        JdkTypes() {
            FileSystem fs = null;
            try {
                fs = FileSystems.getFileSystem(URI.create("jrt:/"));
            } catch (Exception ignored) {
                // not running on a modular JDK
            }
            jrt = fs;
        }

        ClassInfo get(String name) {
            ClassInfo c = cache.get(name);
            if (c != null || jrt == null || missing.contains(name)) return c;
            int slash = name.lastIndexOf('/');
            String pkg = slash < 0 ? "" : name.substring(0, slash).replace('/', '.');
            Path pdir = jrt.getPath("/packages", pkg);
            if (Files.isDirectory(pdir)) {
                try (DirectoryStream<Path> mods = Files.newDirectoryStream(pdir)) {
                    for (Path modLink : mods) {
                        Path file = jrt.getPath("/modules", modLink.getFileName().toString(), name + ".class");
                        if (Files.exists(file)) {
                            byte[] bytes = Files.readAllBytes(file);
                            ClassInfo ci = new ClassInfo(name, "jdk", false, null);
                            new ClassReader(bytes).accept(new HeaderVisitor(ci),
                                    ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                            cache.put(name, ci);
                            return ci;
                        }
                    }
                } catch (IOException | RuntimeException ignored) {
                    // treat as missing
                }
            }
            missing.add(name);
            return null;
        }
    }
}
