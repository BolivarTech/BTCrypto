package com.bolivartech.crypto.digest;

import java.nio.charset.StandardCharsets;

/**
 * Copyright 2007,2009,2010 BolivarTech C.A.
 *
 *  <p>Homepage: <a href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.</p>
 *  <p>BolivarTech Homepage: <a href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 *   This Class is the CuaimaCrypt's CRC32 data checksum used for data integrity validation .
 *
 *   Esta clase realiza el calcula de la redundancia ciclica CRC32 para verificar
 *   la integridad de los datos en la aplicacion
 *   
 *
 * @author Julian Bolivar
 * @since 2010 - December 11, 2010.
 * @version 2.0.0
 */
public class CRC32 extends BaseHash {

    private static final int BLOCK_SIZE = 4; // inner block size in bytes
    /** The digest of the CCPTCRC32 message. */
    private static final String DIGEST0 = "22F9AFAD";
    /** The crc data checksum so far. */
    private int crc = 0;
    /** The fast CRC table. Computed once when the CRC32 class is loaded. */
    private static int[] crc_table = make_crc_table();

    /** Make the table for a fast CRC. */
    private static int[] make_crc_table() {
        int[] crc_table = new int[256];
        for (int n = 0; n < 256; n++) {
            int c = n;
            for (int k = 8; --k >= 0;) {
                if ((c & 1) != 0) {
                    c = 0xedb88320 ^ (c >>> 1);
                } else {
                    c = c >>> 1;
                }
            }
            crc_table[n] = c;
        }
        return crc_table;
    }

    /**
     *  Constructor con la inicalizacion del algoritmo
     */
    public CRC32() {
        super(Registry.CRC32_HASH, 4, BLOCK_SIZE);
        crc = 0;
    }

    /**
     *  Constructor para cloning
     * @param md
     */
    public CRC32(CRC32 md) {
        super(Registry.CRC32_HASH, 4, BLOCK_SIZE);
        crc = md.crc;
    }

    // java.lang.Cloneable interface implementation ----------------------------
    @Override
    public Object clone() {
      return (new CRC32(this));
   }

    /**
     * Returns the CRC32 data checksum computed so far.
     * @return CRC32 data checksum
     */
    public long getValue() {
        return (long) crc & 0xffffffffL;
    }

    /**
     * Resets the CRC32 data checksum as if no update was ever called.
     */
    @Override
    public void reset() {
        crc = 0;
    }

    /**
     * Updates the checksum with the int bval.
     *
     * @param bval (the byte is taken as the lower 8 bits of bval)
     */
    public void update(int bval) {
        int c = ~crc;
        c = crc_table[(c ^ bval) & 0xff] ^ (c >>> 8);
        crc = ~c;
    }

    /**
     * Adds the byte array to the data checksum.
     *
     * @param buf the buffer which contains the data
     * @param off the offset in the buffer where the data starts
     * @param len the length of the data
     */
    @Override
    public void update(byte[] buf, int off, int len) {
        int c = ~crc;
        while (--len >= 0) {
            c = crc_table[(c ^ buf[off++]) & 0xff] ^ (c >>> 8);
        }
        crc = ~c;
    }

    /**
     * Adds the complete byte array to the data checksum.
     * @param buf
     */
    public void update(byte[] buf) {
        update(buf, 0, buf.length);
    }

    /**
     * Retorna el Valor del CRC32 en un arreglo de bytes
     *
     * @return CRC32
     */
    @Override
    public byte[] digest() {

        long val = getValue();
        return new byte[]{(byte) ((val >>> 24) & 0xff),
                          (byte) ((val >>> 16) & 0xff),
                          (byte) ((val >>> 8) & 0xff),
                          (byte) (val & 0xff)};
    }

    /**
     * Realiza una prueba de integridad del algoritmo de CRC32
     *
     * @return TRUE si la prueba fue exitosa y FALSE en caso contrario
     */
    @Override
    public boolean selfTest() {
        
        return DIGEST0.equals(StringUtils.toString(this.Hash("CCPTCRC32".getBytes(StandardCharsets.ISO_8859_1))));
    }

    @Override
    protected byte[] padBuffer() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected byte[] getResult() {
        return this.digest();
    }

    @Override
    protected void resetContext() {
        this.reset();
    }

    @Override
    protected void transform(byte[] in, int offset) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}

/*
public class CRC32 {

    protected long value;
    protected long length;
    protected String encoding;
    public final static String HEX = "hex";


    public CRC32() {
        super();
        crc32 = new CRC32();
    }

    public void reset() {
        crc32.reset();
        length = 0;
    }

    public void update(byte[] buffer, int offset, int len) {
        crc32.update(buffer, offset, len);
        length += len;
    }

    public void update(int b) {
        crc32.update(b);
        length++;
    }

    public void update(byte b) {
        update((int)(b & 0xFF));
    }

    public long getValue() {
        return crc32.getValue();
    }

    public byte[] getByteArray() {
        long val = crc32.getValue();
        return new byte[]
        {(byte)((val>>24)&0xff),
         (byte)((val>>16)&0xff),
         (byte)((val>>8)&0xff),
         (byte)(val&0xff)};
    }

}

*/
