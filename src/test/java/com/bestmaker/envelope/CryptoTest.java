package com.bestmaker.envelope;

import com.bestmaker.envelope.common.Codec;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.crypto.EnvelopeCipher;
import com.bestmaker.envelope.crypto.KeySplitter;
import com.bestmaker.envelope.crypto.Layer;
import com.bestmaker.envelope.crypto.SealedEnvelope;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CryptoTest {
    private final byte[] msg = "B01호, 휠체어".getBytes(StandardCharsets.UTF_8);

    @Test
    void sealAndOpenRoundTrip() {
        byte[] key = EnvelopeCipher.newDataKey();
        SealedEnvelope env = EnvelopeCipher.seal("HH-1", Layer.ENVELOPE_2, 1, msg, key);
        assertFalse(new String(env.ciphertext(), StandardCharsets.UTF_8).contains("B01"));
        assertArrayEquals(msg, EnvelopeCipher.open(env, key));
    }

    @Test
    void swappingEnvelopeToAnotherHouseholdFails() {
        byte[] key = EnvelopeCipher.newDataKey();
        SealedEnvelope env = EnvelopeCipher.seal("HH-1", Layer.ENVELOPE_2, 1, msg, key);
        assertThrows(DeniedException.class, () -> EnvelopeCipher.open(env.relabel("HH-2", Layer.ENVELOPE_2, 1), key));
        assertThrows(DeniedException.class, () -> EnvelopeCipher.open(env.relabel("HH-1", Layer.ENVELOPE_1, 1), key));
        assertThrows(DeniedException.class, () -> EnvelopeCipher.open(env.relabel("HH-1", Layer.ENVELOPE_2, 0), key));
    }

    @Test
    void anyTwoSharesRestoreKeyButOneDoesNot() {
        byte[] key = EnvelopeCipher.newDataKey();
        Map<Integer, byte[]> s = KeySplitter.split(key);
        assertEquals(3, s.size());
        assertArrayEquals(key, KeySplitter.join(Map.of(1, s.get(1), 2, s.get(2))));
        assertArrayEquals(key, KeySplitter.join(Map.of(1, s.get(1), 3, s.get(3))));
        assertArrayEquals(key, KeySplitter.join(Map.of(2, s.get(2), 3, s.get(3))));
        assertThrows(DeniedException.class, () -> KeySplitter.join(Map.of(1, s.get(1))));
    }

    @Test
    void codecRoundTripAndRejectsGarbage() {
        Map<String, String> m = Map.of("a", "1", "구분자,:|", "값");
        assertEquals(m, Codec.decodeMap(Codec.encodeMap(m)));
        assertThrows(IllegalArgumentException.class, () -> Codec.decodeMap(new byte[] {0, 0, 0, 1}));
    }
}
