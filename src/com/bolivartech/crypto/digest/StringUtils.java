package com.bolivartech.crypto.digest;

/**
 * Copyright 2007,2009,2010 BolivarTech C.A.
 *
 *  <p>Homepage: <a href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.</p>
 *  <p>BolivarTech Homepage: <a href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 *   <p>A collection of String utility methods used throughout this project.</p>
 *
 *   
 *
 * @author Julian Bolivar
 * @since 2010 - December 11, 2010.
 * @version 2.0.0
 */

public class StringUtils {

    // Constants and variables
    // -------------------------------------------------------------------------
    // Hex charset
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();
    // Base-64 charset
    private static final String BASE64_CHARS =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";
    private static final char[] BASE64_CHARSET = BASE64_CHARS.toCharArray();

    // Constructor(s)
    // -------------------------------------------------------------------------
    /** Trivial constructor to enforce Singleton pattern. */
    private StringUtils() {
        super();
    }

    // Class methods
    // -------------------------------------------------------------------------
    /**
     * <p>Returns a string of hexadecimal digits from a byte array. Each byte is
     * converted to 2 hex symbols; zero(es) included.</p>
     *
     * <p>This method calls the method with same name and three arguments as:</p>
     *
     * <pre>
     *    toString(ba, 0, ba.length);
     * </pre>
     *
     * @param ba the byte array to convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte array.
     */
    public static String toString(byte[] ba) {
        return toString(ba, 0, ba.length);
    }

    /**
     * <p>Returns a string of hexadecimal digits from a byte array, starting at
     * <code>offset</code> and consisting of <code>length</code> bytes. Each byte
     * is converted to 2 hex symbols; zero(es) included.</p>
     *
     * @param ba the byte array to convert.
     * @param offset the index from which to start considering the bytes to
     * convert.
     * @param length the count of bytes, starting from the designated offset to
     * convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte sub-array.
     */
    public static final String toString(byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length;) {
            k = ba[offset + i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[k & 0x0F];
        }
        return new String(buf);
    }

    /**
     * <p>Returns a string of hexadecimal digits from a byte array. Each byte is
     * converted to 2 hex symbols; zero(es) included. The argument is
     * treated as a large little-endian integer and is returned as a
     * large big-endian integer.</p>
     *
     * <p>This method calls the method with same name and three arguments as:</p>
     *
     * <pre>
     *    toReversedString(ba, 0, ba.length);
     * </pre>
     *
     * @param ba the byte array to convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte array.
     */
    public static String toReversedString(byte[] ba) {
        return toReversedString(ba, 0, ba.length);
    }

    /**
     * <p>Returns a string of hexadecimal digits from a byte array, starting at
     * <code>offset</code> and consisting of <code>length</code> bytes. Each byte
     * is converted to 2 hex symbols; zero(es) included.</p>
     *
     * <p>The byte array is treated as a large little-endian integer, and
     * is returned as a large big-endian integer.</p>
     *
     * @param ba the byte array to convert.
     * @param offset the index from which to start considering the bytes to
     * convert.
     * @param length the count of bytes, starting from the designated offset to
     * convert.
     * @return a string of hexadecimal characters (two for each byte)
     * representing the designated input byte sub-array.
     */
    public static final String toReversedString(byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = offset + length - 1, j = 0, k; i >= offset;) {
            k = ba[offset + i--];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[k & 0x0F];
        }
        return new String(buf);
    }

    /**
     * <p>Returns a byte array from a string of hexadecimal digits.</p>
     *
     * @param s a string of hexadecimal ASCII characters
     * @return the decoded byte array from the input hexadecimal string.
     */
    public static byte[] toBytesFromString(String s) {
        int limit = s.length();
        byte[] result = new byte[((limit + 1) / 2)];
        int i = 0, j = 0;
        if ((limit % 2) == 1) {
            result[j++] = (byte) fromDigit(s.charAt(i++));
        }
        while (i < limit) {
            result[j] = (byte) (fromDigit(s.charAt(i++)) << 4);
            result[j++] |= (byte) fromDigit(s.charAt(i++));
        }
        return result;
    }

    /**
     * <p>Returns a byte array from a string of hexadecimal digits, interpreting
     * them as a large big-endian integer and returning it as a large
     * little-endian integer.</p>
     *
     * @param s a string of hexadecimal ASCII characters
     * @return the decoded byte array from the input hexadecimal string.
     */
    public static byte[] toReversedBytesFromString(String s) {
        int limit = s.length();
        byte[] result = new byte[((limit + 1) / 2)];
        int i = 0;
        if ((limit % 2) == 1) {
            result[i++] = (byte) fromDigit(s.charAt(--limit));
        }
        while (limit > 0) {
            result[i] = (byte) fromDigit(s.charAt(--limit));
            result[i++] |= (byte) (fromDigit(s.charAt(--limit)) << 4);
        }
        return result;
    }

    /**
     * <p>Returns a number from <code>0</code> to <code>15</code> corresponding
     * to the designated hexadecimal digit.</p>
     *
     * @param c a hexadecimal ASCII symbol.
     * @return 
     */
    public static int fromDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        } else if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        } else {
            throw new IllegalArgumentException("Invalid hexadecimal digit: " + c);
        }
    }

    /**
     * <p>Returns a string of 8 hexadecimal digits (most significant digit first)
     * corresponding to the unsigned integer <code>n</code>.</p>
     *
     * @param n the unsigned integer to convert.
     * @return a hexadecimal string 8-character long.
     */
    public static String toString(int n) {
        char[] buf = new char[8];
        for (int i = 7; i >= 0; i--) {
            buf[i] = HEX_DIGITS[n & 0x0F];
            n >>>= 4;
        }
        return new String(buf);
    }

    /**
     * <p>Returns a string of hexadecimal digits from an integer array. Each int
     * is converted to 4 hex symbols.</p>
     * @param ia
     * @return 
     */
    public static String toString(int[] ia) {
        int length = ia.length;
        char[] buf = new char[length * 8];
        for (int i = 0, j = 0, k; i < length; i++) {
            k = ia[i];
            buf[j++] = HEX_DIGITS[(k >>> 28) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 24) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 20) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 16) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 12) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 8) & 0x0F];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[k & 0x0F];
        }
        return new String(buf);
    }

    /**
     * <p>Returns a string of 16 hexadecimal digits (most significant digit first)
     * corresponding to the unsigned long <code>n</code>.</p>
     *
     * @param n the unsigned long to convert.
     * @return a hexadecimal string 16-character long.
     */
    public static String toString(long n) {
        char[] b = new char[16];
        for (int i = 15; i >= 0; i--) {
            b[i] = HEX_DIGITS[(int) (n & 0x0FL)];
            n >>>= 4;
        }
        return new String(b);
    }

    /**
     * <p>Similar to the <code>toString()</code> method except that the Unicode
     * escape character is inserted before every pair of bytes. Useful to
     * externalise byte arrays that will be constructed later from such strings;
     * eg. s-box values.</p>
     *
     * @param ba
     * @return 
     * @throws ArrayIndexOutOfBoundsException if the length is odd.
     */
    public static String toUnicodeString(byte[] ba) {
        return toUnicodeString(ba, 0, ba.length);
    }

    /**
     * <p>Similar to the <code>toString()</code> method except that the Unicode
     * escape character is inserted before every pair of bytes. Useful to
     * externalise byte arrays that will be constructed later from such strings;
     * eg. s-box values.</p>
     *
     * @param ba
     * @param offset
     * @param length
     * @return 
     * @throws ArrayIndexOutOfBoundsException if the length is odd.
     */
    public static final String toUnicodeString(byte[] ba, int offset, int length) {
        StringBuffer sb = new StringBuffer();
        int i = 0;
        int j = 0;
        int k;
        sb.append('\n').append("\"");
        while (i < length) {
            sb.append("\\u");

            k = ba[offset + i++];
            sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
            sb.append(HEX_DIGITS[k & 0x0F]);

            k = ba[offset + i++];
            sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
            sb.append(HEX_DIGITS[k & 0x0F]);

            if ((++j % 8) == 0) {
                sb.append("\"+").append('\n').append("\"");
            }
        }
        sb.append("\"").append('\n');
        return sb.toString();
    }

    /**
     * <p>Similar to the <code>toString()</code> method except that the Unicode
     * escape character is inserted before every pair of bytes. Useful to
     * externalise integer arrays that will be constructed later from such
     * strings; eg. s-box values.</p>
     *
     * @param ia
     * @return 
     * @throws ArrayIndexOutOfBoundsException if the length is not a multiple of 4.
     */
    public static String toUnicodeString(int[] ia) {
        StringBuffer sb = new StringBuffer();
        int i = 0;
        int j = 0;
        int k;
        sb.append('\n').append("\"");
        while (i < ia.length) {
            k = ia[i++];
            sb.append("\\u");
            sb.append(HEX_DIGITS[(k >>> 28) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 24) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 20) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 16) & 0x0F]);
            sb.append("\\u");
            sb.append(HEX_DIGITS[(k >>> 12) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 8) & 0x0F]);
            sb.append(HEX_DIGITS[(k >>> 4) & 0x0F]);
            sb.append(HEX_DIGITS[k & 0x0F]);

            if ((++j % 4) == 0) {
                sb.append("\"+").append('\n').append("\"");
            }
        }
        sb.append("\"").append('\n');
        return sb.toString();
    }

    /**
     *
     * @param s
     * @return
     */
    public static byte[] toBytesFromUnicode(String s) {
        int limit = s.length() * 2;
        byte[] result = new byte[limit];
        char c;
        for (int i = 0; i < limit; i++) {
            c = s.charAt(i >>> 1);
            result[i] = (byte) (((i & 1) == 0) ? c >>> 8 : c);
        }
        return result;
    }

    /**
     * <p>Dumps a byte array as a string, in a format that is easy to read for
     * debugging. The string <code>m</code> is prepended to the start of each
     * line.</p>
     *
     * <p>If <code>offset</code> and <code>length</code> are omitted, the whole
     * array is used. If <code>m</code> is omitted, nothing is prepended to each
     * line.</p>
     *
     * @param data the byte array to be dumped.
     * @param offset the offset within <i>data</i> to start from.
     * @param length the number of bytes to dump.
     * @param m a string to be prepended to each line.
     * @return a string containing the result.
     */
    public static String dumpString(byte[] data, int offset, int length, String m) {
        if (data == null) {
            return m + "null\n";
        }
        StringBuffer sb = new StringBuffer(length * 3);
        if (length > 32) {
            sb.append(m).append("Hexadecimal dump of ").append(length).append(" bytes...\n");
        }
        // each line will list 32 bytes in 4 groups of 8 each
        int end = offset + length;
        String s;
        int l = Integer.toString(length).length();
        if (l < 4) {
            l = 4;
        }
        for (; offset < end; offset += 32) {
            if (length > 32) {
                s = "         " + offset;
                sb.append(m).append(s.substring(s.length() - l)).append(": ");
            }
            int i = 0;
            for (; i < 32 && offset + i + 7 < end; i += 8) {
                sb.append(toString(data, offset + i, 8)).append(' ');
            }
            if (i < 32) {
                for (; i < 32 && offset + i < end; i++) {
                    sb.append(byteToString(data[offset + i]));
                }
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     *
     * @param data
     * @return
     */
    public static String dumpString(byte[] data) {
        return (data == null) ? "null\n" : dumpString(data, 0, data.length, "");
    }

    /**
     *
     * @param data
     * @param m
     * @return
     */
    public static String dumpString(byte[] data, String m) {
        return (data == null) ? "null\n" : dumpString(data, 0, data.length, m);
    }

    /**
     *
     * @param data
     * @param offset
     * @param length
     * @return
     */
    public static String dumpString(byte[] data, int offset, int length) {
        return dumpString(data, offset, length, "");
    }

    /**
     * <p>Returns a string of 2 hexadecimal digits (most significant digit first)
     * corresponding to the lowest 8 bits of <code>n</code>.</p>
     *
     * @param n the byte value to convert.
     * @return a string of 2 hex characters representing the input.
     */
    public static String byteToString(int n) {
        char[] buf = {HEX_DIGITS[(n >>> 4) & 0x0F], HEX_DIGITS[n & 0x0F]};
        return new String(buf);
    }

}
