/*
 * Copyright (c) 2023 VMware, Inc. All Rights Reserved.
 *
 */

package com.gtm.docker;

import com.google.common.io.BaseEncoding;
import com.gtm.Main;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Stream;

/**
 * Insert your comment for {@link DockerKeyIdentifier}.
 *
 * @author kumargautam
 */
public class DockerKeyIdentifier {

    public static String generateKeyID(PrivateKey key) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(Main.pemToDer());
            byte[] hashed = sha256.digest();
            byte[] hashedTruncated = truncateToBitLength(240, hashed);
            String base32Id = Base32.encode(hashedTruncated);
            System.out.println(base32Id);
            /*org.apache.commons.codec.binary.Base32 base32 = new org.apache.commons.codec.binary.Base32();
            String base32Id1 = base32.encodeAsString(hashedTruncated);
            System.out.println(base32Id1);
            String base32Id2 = BaseEncoding.base32().encode(hashedTruncated);
            System.out.println(base32Id2);*/
            return (String) byteStream(base32Id.getBytes(StandardCharsets.UTF_8)).collect(new DelimitingCollector());
        } catch (Exception e) {
            throw new RuntimeException("Unable to generate Key ID", e);
        }
    }

    private static byte[] truncateToBitLength(int bitLength, byte[] arrayToTruncate) {
        if (bitLength % 8 != 0) {
            throw new IllegalArgumentException("Bit length for truncation of byte array given as a number not divisible by 8");
        } else {
            int numberOfBytes = bitLength / 8;
            return Arrays.copyOfRange(arrayToTruncate, 0, numberOfBytes);
        }
    }

    private static Stream<Byte> byteStream(byte[] bytes) {
        Collection<Byte> colectionedBytes = new ArrayList();
        byte[] var3 = bytes;
        int var4 = bytes.length;

        for (int var5 = 0; var5 < var4; ++var5) {
            byte aByte = var3[var5];
            colectionedBytes.add(aByte);
        }

        return colectionedBytes.stream();
    }

    public static class DelimitingCollector implements Collector<Byte, StringBuilder, String> {
        public DelimitingCollector() {
        }

        public Supplier<StringBuilder> supplier() {
            return () -> {
                return new StringBuilder();
            };
        }

        public BiConsumer<StringBuilder, Byte> accumulator() {
            return (stringBuilder, aByte) -> {
                if (needsDelimiter(4, ":", stringBuilder)) {
                    stringBuilder.append(":");
                }

                stringBuilder.append(new String(new byte[]{aByte}));
            };
        }

        private static boolean needsDelimiter(int maxLength, String delimiter, StringBuilder builder) {
            int lastDelimiter = builder.lastIndexOf(delimiter);
            int charsSinceLastDelimiter = builder.length() - lastDelimiter;
            return charsSinceLastDelimiter > maxLength;
        }

        public BinaryOperator<StringBuilder> combiner() {
            return (left, right) -> {
                return (new StringBuilder(left.toString())).append(right.toString());
            };
        }

        public Function<StringBuilder, String> finisher() {
            return StringBuilder::toString;
        }

        public Set<Characteristics> characteristics() {
            return Collections.emptySet();
        }
    }
}
