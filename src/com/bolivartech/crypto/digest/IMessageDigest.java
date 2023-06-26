package com.bolivartech.crypto.digest;

/**
 * <p>The basic visible methods of any hash algorithm.</p>
 *
 * <p>A hash (or message digest) algorithm produces its output by iterating a
 * basic compression function on blocks of data.</p>
 *
 * @author Julian Bolivar
 * @since 2010 - March 17, 2014.
 * @version $Revision: 2.0 $
 */
public interface IMessageDigest { //extends Cloneable {

   // Constants
   // -------------------------------------------------------------------------

   // Methods
   // -------------------------------------------------------------------------

   /**
    * <p>Returns the canonical name of this algorithm.</p>
    *
    * @return the canonical name of this instance.
    */
   String name();

   /**
    * <p>Returns the output length in bytes of this message digest algorithm.</p>
    *
    * @return the output length in bytes of this message digest algorithm.
    */
   int hashSize();

   /**
    * <p>Returns the algorithm's (inner) block size in bytes.</p>
    *
    * @return the algorithm's inner block size in bytes.
    */
   int blockSize();

   /**
    * <p>Continues a message digest operation using the input byte.</p>
    *
    * @param b the input byte to digest.
    */
   void update(byte b);

   /**
    * <p>Continues a message digest operation, by filling the buffer, processing
    * data in the algorithm's HASH_SIZE-bit block(s), updating the context and
    * count, and buffering the remaining bytes in buffer for the next
    * operation.</p>
    *
    * @param in the input block.
    * @param offset start of meaningful bytes in input block.
    * @param length number of bytes, in input block, to consider.
    */
   void update(byte[] in, int offset, int length);

   /**
    * <p>Completes the message digest by performing final operations such as
    * padding and resetting the instance.</p>
    *
    * @return the array of bytes representing the hash value.
    */
   byte[] digest();

   /**
    * <p>Resets the current context of this instance clearing any eventually cached
    * intermediary values.</p>
    */
   void reset();

   /**
    * <p>A basic test. Ensures that the digest of a pre-determined message is equal
    * to a known pre-computed value.</p>
    *
    * @return <tt>true</tt> if the implementation passes a basic self-test.
    * Returns <tt>false</tt> otherwise.
    */
   boolean selfTest();

   /**
    * <p>Returns a clone copy of this instance.</p>
    *
    * @return a clone copy of this instance.
    */
   Object clone();

   /**
    * Realiza el calculo del HASH del arreglo de bytes de entrada
    *
    * @param Input
    * @return HASH de la entrada
    */
   public byte[] Hash(byte[] Input);

   /**
    * Realiza el calculo del HASH del Mensaje de Entrada
    *
    * @param Message
    * @return HASH del mensaje de entrada
    */
   public byte[] Hash(String Message);
   
    /**
     * Calcula el HASH de la entrada de un arreglo de long
     *
     * @param Input con un arreglo de long
     * @return HASH del mensaje de entrada
     */
    public byte[] Hash(long[] Input);
    
    /**
     * Calcula el HASH de la entrada de un arreglo de int
     *
     * @param Input con un arreglo de int
     * @return HASH del mensaje de entrada
     */
    public byte[] Hash(int[] Input);

}

