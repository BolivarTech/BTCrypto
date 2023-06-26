package com.bolivartech.crypto.digest;

/**
 *
 * @author Julian Bolivar
 * @since 2010 - December 11, 2010
 * @version $Revision: 2.0 $
 */

public class Tiger128 extends Tiger {

   /** Result when no data has been input. */
   private static final String DIGEST0 = "3293AC630C13F0245F92BBB1766E1616";


   /**
    * Trivial 0-arguments constructor.
    */
   public Tiger128() {
      super();
      name=Registry.TIGER128_HASH;
   }

   /**
    * Private copying constructor for cloning.
    *
    * @param that The instance being cloned.
    */
   private Tiger128(Tiger128 that) {
      this();
      this.a = that.a;
      this.b = that.b;
      this.c = that.c;
      this.count = that.count;
      this.buffer = (that.buffer != null) ? (byte[]) that.buffer.clone() : null;
   }

   @Override
   public Object clone() {
      return new Tiger128(this);
   }

   @Override
   public boolean selfTest() {

       return DIGEST0.equals(StringUtils.toString(new Tiger128().digest()));
   }


   @Override
   protected byte[] getResult() {
      return new byte[] {
         (byte) a        , (byte)(a >>>  8), (byte)(a >>> 16),
         (byte)(a >>> 24), (byte)(a >>> 32), (byte)(a >>> 40),
         (byte)(a >>> 48), (byte)(a >>> 56),
         (byte) b        , (byte)(b >>>  8), (byte)(b >>> 16),
         (byte)(b >>> 24), (byte)(b >>> 32), (byte)(b >>> 40),
         (byte)(b >>> 48), (byte)(b >>> 56)
      };
   }

    @Override
   public int hashSize() {
      return 16;
   }

}
