package com.bestmaker.envelope.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * 길이 접두 인코딩. 서명·AAD·해시 입력이 구분자 충돌로 모호해지지 않게 하고,
 * Java 직렬화(ObjectInputStream)를 쓰지 않기 위한 최소 포맷이다.
 */
public final class Codec {
    private static final int MAX_FIELD = 1 << 20;

    private Codec() {
    }

    public static byte[] fields(String... parts) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buf)) {
            out.writeInt(parts.length);
            for (String p : parts) {
                byte[] b = (p == null ? "" : p).getBytes(StandardCharsets.UTF_8);
                out.writeInt(b.length);
                out.write(b);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buf.toByteArray();
    }

    public static byte[] encodeMap(Map<String, String> map) {
        TreeMap<String, String> sorted = new TreeMap<>(map);
        String[] parts = new String[sorted.size() * 2];
        int i = 0;
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            parts[i++] = e.getKey();
            parts[i++] = e.getValue();
        }
        return fields(parts);
    }

    public static Map<String, String> decodeMap(byte[] data) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            int n = in.readInt();
            if (n < 0 || n % 2 != 0 || n > 10_000) {
                throw new IllegalArgumentException("잘못된 인코딩");
            }
            Map<String, String> map = new TreeMap<>();
            for (int i = 0; i < n; i += 2) {
                map.put(readString(in), readString(in));
            }
            if (in.available() != 0) {
                throw new IllegalArgumentException("잘못된 인코딩");
            }
            return map;
        } catch (IOException e) {
            throw new IllegalArgumentException("잘못된 인코딩", e);
        }
    }

    private static String readString(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 0 || len > MAX_FIELD) {
            throw new IOException("필드 길이 초과");
        }
        byte[] b = in.readNBytes(len);
        if (b.length != len) {
            throw new IOException("잘린 입력");
        }
        return new String(b, StandardCharsets.UTF_8);
    }
}
