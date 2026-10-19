package com.logssey.iac.run;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.zip.GZIPOutputStream;

/** src/test/resources/iac 의 plan fixture 를 gzip 으로 돌려준다. */
public final class IacPlanFixtures {
    private IacPlanFixtures() { }

    public static byte[] gzipResource(String name) {
        try (InputStream in = IacPlanFixtures.class.getResourceAsStream("/iac/" + name)) {
            if (in == null) throw new IllegalArgumentException(name);
            return gzip(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] gzip(byte[] raw) {
        var out = new ByteArrayOutputStream();
        try (var gz = new GZIPOutputStream(out)) {
            gz.write(raw);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }
}
