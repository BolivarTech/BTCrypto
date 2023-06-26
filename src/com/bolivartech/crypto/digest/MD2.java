package com.bolivartech.crypto.digest;

/**
 * <p>An implementation of the MD2 message digest algorithm.</p>
 *
 * <p>MD2 is not widely used. Unless it is needed for compatibility with
 * existing systems, it is not recommended for use in new applications.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li>The <a href="http://www.ietf.org/rfc/rfc1319.txt">MD2</a>
 *    Message-Digest Algorithm.<br>
 *    B. Kaliski.</li>
 *    <li>The <a href="http://www.rfc-editor.org/errata.html">RFC ERRATA PAGE</a>
 *    under section RFC 1319.</li>
 * </ol>
 *
 * @author Julian Bolivar
 * @since 2010 - December 11, 2010
 * @version $Revision: 1.0 $
 */
public class MD2 extends BaseHash {

   // Constants and variables
   // -------------------------------------------------------------------------

   /** An MD2 message digest is always 128-bits long, or 16 bytes. */
   private static final int DIGEST_LENGTH = 16;

   /** The MD2 algorithm operates on 128-bit blocks, or 16 bytes. */
   private static final int BLOCK_LENGTH = 16;

   /** 256 byte "random" permutation of the digits of pi. */
   private static final byte[] PI = {
      41, 46, 67, -55, -94, -40, 124, 1, 61, 54, 84, -95, -20, -16, 6,
      19, 98, -89, 5, -13, -64, -57, 115, -116, -104, -109, 43, -39,
      -68, 76, -126, -54, 30, -101, 87, 60, -3, -44, -32, 22, 103, 66,
      111, 24, -118, 23, -27, 18, -66, 78, -60, -42, -38, -98, -34, 73,
      -96, -5, -11, -114, -69, 47, -18, 122, -87, 104, 121, -111, 21,
      -78, 7, 63, -108, -62, 16, -119, 11, 34, 95, 33, -128, 127, 93,
      -102, 90, -112, 50, 39, 53, 62, -52, -25, -65, -9, -105, 3, -1,
      25, 48, -77, 72, -91, -75, -47, -41, 94, -110, 42, -84, 86, -86,
      -58, 79, -72, 56, -46, -106, -92, 125, -74, 118, -4, 107, -30,
      -100, 116, 4, -15, 69, -99, 112, 89, 100, 113, -121, 32, -122,
      91, -49, 101, -26, 45, -88, 2, 27, 96, 37, -83, -82, -80, -71,
      -10, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, -93, 35, -35, 81,
      -81, 58, -61, 92, -7, -50, -70, -59, -22, 38, 44, 83, 13, 110,
      -123, 40, -124, 9, -45, -33, -51, -12, 65, -127, 77, 82, 106,
      -36, 55, -56, 108, -63, -85, -6, 36, -31, 123, 8, 12, -67, -79,
      74, 120, -120, -107, -117, -29, 99, -24, 109, -23, -53, -43, -2,
      59, 0, 29, 57, -14, -17, -73, 14, 102, 88, -48, -28, -90, 119,
      114, -8, -21, 117, 75, 10, 49, 68, 80, -76, -113, -19, 31, 26,
      -37, -103, -115, 51, -97, 17, -125, 20
   };

   /** The output of this message digest when no data has been input. */
   private static final String DIGEST0 = "8350E5A3E24C153DF2275C9F80692773";

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   /** The checksum computed so far. */
   private byte[] checksum;

   /**
    * Work array needed by encrypt method. First <code>BLOCK_LENGTH</code> bytes
    * are also used to store the running digest.
    */
   private byte[] work;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Creates a new MD2 digest ready for use. */
   public MD2() {
      super(Registry.MD2_HASH, DIGEST_LENGTH, BLOCK_LENGTH);
   }

   /**
    * <p>Private constructor used for cloning.</p>
    *
    * @param md2 the instance to clone.
    */
   private MD2(MD2 md2) {
      this();

      // superclass field
      this.count = md2.count;
      this.buffer = (byte[]) md2.buffer.clone();

      // private field
      this.checksum = (byte[]) md2.checksum.clone();
      this.work = (byte[]) md2.work.clone();
   }

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   @Override
   public Object clone() {
      return new MD2(this);
   }

   // Implementation of abstract methods in BaseHash --------------------------

   @Override
   protected byte[] getResult() {
      byte[] result = new byte[DIGEST_LENGTH];

      // Encrypt checksum as last block.
      encryptBlock(checksum, 0);
      System.arraycopy(work, 0, result, 0, BLOCK_LENGTH);
/*      for (int i = 0; i < BLOCK_LENGTH; i++) {
         result[i] = work[i];
      } */
      return result;
   }

   @Override
   protected void resetContext() {
      checksum = new byte[BLOCK_LENGTH];
      work = new byte[BLOCK_LENGTH*3];
   }

   @Override
   public boolean selfTest() {
      MD2 Test;
       
      if (valid == null) {
         Test = new MD2();
         valid = DIGEST0.equals(StringUtils.toString(Test.digest()));
      }
      return valid.booleanValue();
   }

   /**
    * <p>Generates an array of padding bytes. The padding is defined as
    * <code>i</code> bytes of value <code>i</code>, where <code>i</code> is the
    * number of bytes to fill the last block of the message to
    * <code>BLOCK_LENGTH</code> bytes (or <code>BLOCK_LENGTH</code> bytes when
    * the last block was completely full).</p>
    *
    * @return the bytes to pad the remaining bytes in the buffer before
    * completing a hash operation.
    */
   @Override
   protected byte[] padBuffer() {
      int length = BLOCK_LENGTH - (int)(count % BLOCK_LENGTH);
      if (length == 0) {
         length = BLOCK_LENGTH;
      }
      byte[] pad = new byte[length];
      for (int i = 0; i < length; i++) {
         pad[i] = (byte) length;
      }
      return pad;
   }

   /**
    * <p>Adds <code>BLOCK_LENGTH</code> bytes to the running digest.</p>
    *
    * @param in the byte array to take the <code>BLOCK_LENGTH</code> bytes from.
    * @param off the offset to start from in the given byte array.
    */
   @Override
   protected void transform(byte[] in, int off) {
      // encryptBlock(in, off);
      // updateCheckSum(in, off);
      updateCheckSumAndEncryptBlock(in, off);
   }

   // Private instance methods ------------------------------------------------

   /**
    * Updates the checksum with the <code>BLOCK_LENGTH</code> bytes from the
    * given array starting at <code>off</code>.
    */
/*
   private void updateCheckSum(byte[] in, int off) {
      byte l = checksum[BLOCK_LENGTH-1];
      for (int i = 0; i < BLOCK_LENGTH; i++) {
         byte b = in[off+i];
//         l = (byte)((checksum[i] & 0xFF) ^ (PI[((b & 0xFF) ^ (l & 0xFF))] & 0xFF));
         l = (byte)(checksum[i] ^ PI[(b ^ l) & 0xFF]);
         checksum[i] = l;
      }
   }
*/
   /**
    * Adds a new block (<code>BLOCK_LENGTH</code> bytes) to the running digest
    * from the given byte array starting from the given offset.
    */
   private void encryptBlock(byte[] in, int off) {
      for (int i = 0; i < BLOCK_LENGTH; i++) {
         byte b = in[off+i];
         work[BLOCK_LENGTH+i] = b;
         work[BLOCK_LENGTH*2+i] = (byte)(work[i] ^ b);
      }

      byte t = 0;
      for (int i = 0; i < 18; i++) {
         for (int j = 0; j < 3 * BLOCK_LENGTH; j++) {
//            t = (byte)((work[j] & 0xFF) ^ (PI[t & 0xFF] & 0xFF));
            t = (byte)(work[j] ^ PI[t & 0xFF]);
            work[j] = t;
         }
//         t = (byte)((t + i) & 0xFF);
         t = (byte)(t + i);
      }
   }

   /**
    * Optimized method that combines a checksum update and encrypt of a block.
    */
   private void updateCheckSumAndEncryptBlock(byte[] in, int off) {
      byte l = checksum[BLOCK_LENGTH-1];
      for (int i = 0; i < BLOCK_LENGTH; i++) {
         byte b = in[off+i];
         work[BLOCK_LENGTH+i] = b;
//         work[BLOCK_LENGTH*2+i] = (byte)((work[i] & 0xFF) ^ (b & 0xFF));
         work[BLOCK_LENGTH*2+i] = (byte)(work[i] ^ b);
//         l = (byte)((checksum[i] & 0xFF) ^ (PI[((b & 0xFF) ^ (l & 0xFF))] & 0xFF));
         l = (byte)(checksum[i] ^ PI[(b ^ l) & 0xFF]);
        checksum[i] = l;
      }

      byte t = 0;
      for (int i = 0; i < 18; i++) {
         for (int j = 0; j < 3 * BLOCK_LENGTH; j++) {
//            t = (byte)((work[j] & 0xFF) ^ (PI[t & 0xFF] & 0xFF));
            t = (byte)(work[j] ^ PI[t & 0xFF]);
            work[j] = t;
         }
//         t = (byte)((t + i) & 0xFF);
         t = (byte)(t + i);
      }
   }

}
