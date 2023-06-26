package com.bolivartech.crypto.digest;

/**
 * <p>The Secure Hash Algorithm (SHA-1) is required for use with the Digital
 * Signature Algorithm (DSA) as specified in the Digital Signature Standard
 * (DSS) and whenever a secure hash algorithm is required for federal
 * applications. For a message of length less than 2^64 bits, the SHA-1
 * produces a 160-bit condensed representation of the message called a message
 * digest. The message digest is used during generation of a signature for the
 * message. The SHA-1 is also used to compute a message digest for the received
 * version of the message during the process of verifying the signature. Any
 * change to the message in transit will, with very high probability, result in
 * a different message digest, and the signature will fail to verify.</p>
 *
 * <p>The SHA-1 is designed to have the following properties: it is
 * computationally infeasible to find a message which corresponds to a given
 * message digest, or to find two different messages which produce the same
 * message digest.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://www.itl.nist.gov/fipspubs/fip180-1.htm">SECURE HASH
 *    STANDARD</a><br>
 *    Federal Information, Processing Standards Publication 180-1, 1995 April 17.
 *    </li>
 * </ol>
 *
 * @author Julian Bolivar
 * @since 2010 - December 11, 2010
 * @version $Revision: 2.0 $
 */
public class Sha160 extends BaseHash {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int BLOCK_SIZE = 64; // inner block size in bytes

   private static final String DIGEST0 = "A9993E364706816ABA3E25717850C26C9CD0D89D";

   private static final int[] w = new int[80];

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   /** 160-bit interim result. */
   private int h0, h1, h2, h3, h4;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public Sha160() {
      super(Registry.SHA160_HASH, 20, BLOCK_SIZE);
   }

   /**
    * <p>Private constructor for cloning purposes.</p>
    *
    * @param md the instance to clone.
    */
   private Sha160(Sha160 md) {
      this();

      this.h0 = md.h0;
      this.h1 = md.h1;
      this.h2 = md.h2;
      this.h3 = md.h3;
      this.h4 = md.h4;
      this.count = md.count;
      this.buffer = (byte[]) md.buffer.clone();
   }

   // Class methods
   // -------------------------------------------------------------------------

    /**
     *
     * @param hh0
     * @param hh1
     * @param hh2
     * @param hh3
     * @param hh4
     * @param in
     * @param offset
     * @return
     */
    
   public static final int[]
   G(int hh0, int hh1, int hh2, int hh3, int hh4, byte[] in, int offset) {
//      int[] w = new int[80];
//      int i, T;
//      for (i = 0; i < 16; i++) {
//         w[i] = in[offset++]         << 24 |
//               (in[offset++] & 0xFF) << 16 |
//               (in[offset++] & 0xFF) <<  8 |
//               (in[offset++] & 0xFF);
//      }
//      for (i = 16; i < 80; i++) {
//         T = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
//         w[i] = T << 1 | T >>> 31;
//      }

//      return sha(hh0, hh1, hh2, hh3, hh4, in, offset, w);
      return sha(hh0, hh1, hh2, hh3, hh4, in, offset);
   }

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   @Override
   public Object clone() {
      return new Sha160(this);
   }

   // Implementation of concrete methods in BaseHash --------------------------

   @Override
   protected void transform(byte[] in, int offset) {
//      int i, T;
//      for (i = 0; i < 16; i++) {
//         W[i] = in[offset++]         << 24 |
//               (in[offset++] & 0xFF) << 16 |
//               (in[offset++] & 0xFF) <<  8 |
//               (in[offset++] & 0xFF);
//      }
//      for (i = 16; i < 80; i++) {
//         T = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
//         W[i] = T << 1 | T >>> 31;
//      }

//      int[] result = sha(h0, h1, h2, h3, h4, in, offset, W);
      int[] result = sha(h0, h1, h2, h3, h4, in, offset);

      h0 = result[0];
      h1 = result[1];
      h2 = result[2];
      h3 = result[3];
      h4 = result[4];
   }

   @Override
   protected byte[] padBuffer() {
      int n = (int)(count % BLOCK_SIZE);
      int padding = (n < 56) ? (56 - n) : (120 - n);
      byte[] result = new byte[padding + 8];

      // padding is always binary 1 followed by binary 0s
      result[0] = (byte) 0x80;

      // save number of bits, casting the long to an array of 8 bytes
      long bits = count << 3;
      result[padding++] = (byte)(bits >>> 56);
      result[padding++] = (byte)(bits >>> 48);
      result[padding++] = (byte)(bits >>> 40);
      result[padding++] = (byte)(bits >>> 32);
      result[padding++] = (byte)(bits >>> 24);
      result[padding++] = (byte)(bits >>> 16);
      result[padding++] = (byte)(bits >>>  8);
      result[padding  ] = (byte) bits;

      return result;
   }

   @Override
   protected byte[] getResult() {
      byte[] result = new byte[] {
         (byte)(h0 >>> 24), (byte)(h0 >>> 16), (byte)(h0 >>> 8), (byte) h0,
         (byte)(h1 >>> 24), (byte)(h1 >>> 16), (byte)(h1 >>> 8), (byte) h1,
         (byte)(h2 >>> 24), (byte)(h2 >>> 16), (byte)(h2 >>> 8), (byte) h2,
         (byte)(h3 >>> 24), (byte)(h3 >>> 16), (byte)(h3 >>> 8), (byte) h3,
         (byte)(h4 >>> 24), (byte)(h4 >>> 16), (byte)(h4 >>> 8), (byte) h4
      };

      return result;
   }

   @Override
   protected void resetContext() {
      // magic SHA-1/RIPEMD160 initialisation constants
      h0 = 0x67452301;
      h1 = 0xEFCDAB89;
      h2 = 0x98BADCFE;
      h3 = 0x10325476;
      h4 = 0xC3D2E1F0;
   }

   @Override
   public boolean selfTest() {
      if (valid == null) {
         Sha160 md = new Sha160();
         md.update((byte) 0x61); // a
         md.update((byte) 0x62); // b
         md.update((byte) 0x63); // c
         String result = StringUtils.toString(md.digest());
         valid = DIGEST0.equals(result);
      }
      return valid.booleanValue();
   }

   // SHA specific methods ----------------------------------------------------

   private static synchronized int[] 
//   sha(int hh0, int hh1, int hh2, int hh3, int hh4, byte[] in, int offset, int[] w) {
   sha(int hh0, int hh1, int hh2, int hh3, int hh4, byte[] in, int offset) {
      int A = hh0;
      int B = hh1;
      int C = hh2;
      int D = hh3;
      int E = hh4;
      int r, T;

      for (r = 0; r < 16; r++) {
         w[r] = in[offset++]         << 24 |
               (in[offset++] & 0xFF) << 16 |
               (in[offset++] & 0xFF) <<  8 |
               (in[offset++] & 0xFF);
      }
      for (r = 16; r < 80; r++) {
         T = w[r-3] ^ w[r-8] ^ w[r-14] ^ w[r-16];
         w[r] = T << 1 | T >>> 31;
      }

      // rounds 0-19
      for (r = 0; r < 20; r++) {
         T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + w[r] + 0x5A827999;
         E = D;
         D = C;
         C = B << 30 | B >>> 2;
         B = A;
         A = T;
      }

      // rounds 20-39
      for (r = 20; r < 40; r++) {
         T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + w[r] + 0x6ED9EBA1;
         E = D;
         D = C;
         C = B << 30 | B >>> 2;
         B = A;
         A = T;
      }

      // rounds 40-59
      for (r = 40; r < 60; r++) {
         T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + w[r] + 0x8F1BBCDC;
         E = D;
         D = C;
         C = B << 30 | B >>> 2;
         B = A;
         A = T;
      }

      // rounds 60-79
      for (r = 60; r < 80; r++) {
         T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + w[r] + 0xCA62C1D6;
         E = D;
         D = C;
         C = B << 30 | B >>> 2;
         B = A;
         A = T;
      }

      return new int[] {hh0+A, hh1+B, hh2+C, hh3+D, hh4+E};
   }

}
