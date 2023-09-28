/*
 * Copyright (c) 2023 VMware, Inc. All Rights Reserved.
 *
 */

package com.gtm.docker;

/**
 * Insert your comment for {@link Base32}.
 *
 * @author kumargautam
 */
public class Base32 {

    private static final String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int[] base32Lookup = new int[]{255, 255, 26, 27, 28, 29, 30, 31, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255};

    public Base32() {
    }

    public static String encode(byte[] bytes) {
        int i = 0;
        int index = 0;

        StringBuffer base32;
        int digit;
        for (base32 = new StringBuffer((bytes.length + 7) * 8 / 5); i < bytes.length; base32.append(base32Chars.charAt(digit))) {
            int currByte = bytes[i] >= 0 ? bytes[i] : bytes[i] + 256;
            if (index > 3) {
                int nextByte;
                if (i + 1 < bytes.length) {
                    nextByte = bytes[i + 1] >= 0 ? bytes[i + 1] : bytes[i + 1] + 256;
                } else {
                    nextByte = 0;
                }

                digit = currByte & 255 >> index;
                index = (index + 5) % 8;
                digit <<= index;
                digit |= nextByte >> 8 - index;
                ++i;
            } else {
                digit = currByte >> 8 - (index + 5) & 31;
                index = (index + 5) % 8;
                if (index == 0) {
                    ++i;
                }
            }
        }

        return base32.toString();
    }

    public static byte[] decode(String base32) {
        byte[] bytes = new byte[base32.length() * 5 / 8];
        int i = 0;
        int index = 0;

        for (int offset = 0; i < base32.length(); ++i) {
            int lookup = base32.charAt(i) - 48;
            if (lookup >= 0 && lookup < base32Lookup.length) {
                int digit = base32Lookup[lookup];
                if (digit != 255) {
                    if (index <= 3) {
                        index = (index + 5) % 8;
                        if (index == 0) {
                            bytes[offset] = (byte) (bytes[offset] | digit);
                            ++offset;
                            if (offset >= bytes.length) {
                                break;
                            }
                        } else {
                            bytes[offset] = (byte) (bytes[offset] | digit << 8 - index);
                        }
                    } else {
                        index = (index + 5) % 8;
                        bytes[offset] = (byte) (bytes[offset] | digit >>> index);
                        ++offset;
                        if (offset >= bytes.length) {
                            break;
                        }

                        bytes[offset] = (byte) (bytes[offset] | digit << 8 - index);
                    }
                }
            }
        }
        return bytes;
    }
}
