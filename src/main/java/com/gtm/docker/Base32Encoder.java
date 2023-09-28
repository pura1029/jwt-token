/*
 * Copyright (c) 2023 VMware, Inc. All Rights Reserved.
 *
 */

package com.gtm.docker;

/**
 * Insert your comment for {@link Base32Encoder}.
 *
 * @author kumargautam
 */

public class Base32Encoder {
    private static final char[] B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    public static byte[] b32encode(byte[] s) {
        int leftover = s.length % 5;
        if (leftover != 0) {
            byte[] padded = new byte[s.length + (5 - leftover)];
            System.arraycopy(s, 0, padded, 0, s.length);
            s = padded;
        }

        byte[] encoded = new byte[s.length * 8 / 5];
        int encodedIndex = 0;

        for (int i = 0; i < s.length; i += 5) {
            long c = ((long) (s[i] & 0xFF) << 32) |
                    ((long) (s[i + 1] & 0xFF) << 24) |
                    ((long) (s[i + 2] & 0xFF) << 16) |
                    ((long) (s[i + 3] & 0xFF) << 8) |
                    (s[i + 4] & 0xFF);

            for (int j = 0; j < 8; j++) {
                int index = (int) ((c >> (35 - j * 5)) & 0x1F);
                encoded[encodedIndex++] = (byte) B32_ALPHABET[index];
            }
        }

        return encoded;
    }

    public static void main(String[] args) {
        byte[] input = "Hello, World!".getBytes();
        byte[] encoded = b32encode(input);
        System.out.println(new String(encoded)); // Print the Base32 encoded string
    }
}


