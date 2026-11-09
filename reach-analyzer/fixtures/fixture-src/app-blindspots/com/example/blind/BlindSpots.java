package com.example.blind;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.springframework.stereotype.Service;

/**
 * Shapes static analysis cannot see (reflection, type names from strings), plus a mix-in.
 * The first two are known misses and pin the documented limitation; the mix-in must not be over-reported.
 */
@Service
public class BlindSpots {
    private static final String MODES = "org.bouncycastle.crypto.modes.";

    public static class PriceTick {
        public String symbol;
        public BigDecimal price;
    }

    public static class Node {
        public String label;
        public Node next;
    }

    @JsonIdentityInfo(generator = ObjectIdGenerators.IntSequenceGenerator.class)
    abstract static class NodeIdentityMixIn {
    }

    /** CVE-2025-14813 via reflection: G3413CTRBlockCipher is never named in bytecode. */
    public StreamCipher ctrByName(String mode) throws Exception {
        return (StreamCipher) Class.forName(MODES + mode).getConstructor(BlockCipher.class).newInstance(new GOST3412_2015Engine());
    }

    /** CVE-2026-89407 via a runtime type name: PriceTick is never named in bytecode. */
    public Object readByTypeName(String json, String typeName) throws Exception {
        return new ObjectMapper().readValue(json, Class.forName(typeName));
    }

    /** CVE-2026-91777: identity info through a mix-in, on a single object (no collection or map). */
    public Node readGraph(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper().addMixIn(Node.class, NodeIdentityMixIn.class);
        return mapper.readValue(json, Node.class);
    }
}
