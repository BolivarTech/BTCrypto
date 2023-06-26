package com.bolivartech.crypto.digest;

import com.bolivartech.utils.converters.Converter;
import java.nio.charset.StandardCharsets;

/**
 * <p>A base abstract class to facilitate hash implementations.</p>
 *
 * @author Julian Bolivar
 * @since 2010 - March 17, 2014.
 * @version $Revision: 2.0 $
 */
public abstract class BaseHash implements IMessageDigest {

   // Constants and variables
   // -------------------------------------------------------------------------

   /** The canonical name prefix of the hash. */
   protected String name;

   /** The hash (output) size in bytes. */
   protected int hashSize;

   /** The hash (inner) block size in bytes. */
   protected int blockSize;

   /** Number of bytes processed so far. */
   protected long count;

   /** Temporary input buffer. */
   protected byte[] buffer;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /**
    * <p>Trivial constructor for use by concrete subclasses.</p>
    *
    * @param name the canonical name prefix of this instance.
    * @param hashSize the block size of the output in bytes.
    * @param blockSize the block size of the internal transform.
    */
   protected BaseHash(String name, int hashSize, int blockSize) {
      super();

      this.name = name;
      this.hashSize = hashSize;
      this.blockSize = blockSize;
      this.buffer = new byte[blockSize];
      resetContext();
   }

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   // IMessageDigest interface implementation ---------------------------------

   @Override
   public String name() {
      return name;
   }

   @Override
   public int hashSize() {
      return hashSize;
   }

   @Override
   public int blockSize() {
      return blockSize;
   }

   @Override
   public void update(byte b) {
      // compute number of bytes still unhashed; ie. present in buffer
      int i = (int)(count % blockSize);
      count++;
      buffer[i] = b;
      if (i == (blockSize - 1)) {
         transform(buffer, 0);
      }
   }

   @Override
   public void update(byte[] b, int offset, int len) {
      int n = (int)(count % blockSize);
      count += len;
      int partLen = blockSize - n;
      int i = 0;

      if (len >= partLen) {
         System.arraycopy(b, offset, buffer, n, partLen);
         transform(buffer, 0);
         for (i = partLen; i + blockSize - 1 < len; i+= blockSize) {
            transform(b, offset + i);
         }
         n = 0;
      }

      if (i < len) {
         System.arraycopy(b, offset + i, buffer, n, len - i);
      }
   }

   @Override
   public byte[] digest() {
      byte[] tail = padBuffer(); // pad remaining bytes in buffer
      update(tail, 0, tail.length); // last transform of a message
      byte[] result = getResult(); // make a result out of context

      reset(); // reset this instance for future re-use

      return result;
   }

   @Override
   public void reset() { // reset this instance for future re-use
      count = 0L;
      for (int i = 0; i < blockSize; ) {
         buffer[i++] = 0;
      }

      resetContext();
   }

      /**
    * Realiza el calculo del HASH del arreglo de bytes de entrada
    *
    * @param Input
    * @return HASH de la entrada
    */
   @Override
   public byte[] Hash(byte[] Input){

       this.reset();
       this.update(Input, 0, Input.length);
       return this.digest();
   }

   /**
    * Realiza el calculo del HASH del Mensaje de Entrada
    *
    * @param Message
    * @return HASH del mensaje de entrada
    */
   @Override
   public byte[] Hash(String Message){
       byte[] Intermedio;
       
       this.reset();
       Intermedio = Message.getBytes(StandardCharsets.UTF_16); 
       this.update(Intermedio, 0, Intermedio.length);
       return this.digest();
   }
   
     /**
     * Calcula el HASH de la entrada de un arreglo de long
     *
     * @param Input con un arreglo de long
     * @return HASH del mensaje de entrada
     */
   @Override
    public byte[] Hash(long[] Input) {
        byte[] Entrada;

        this.reset();
        Entrada = Converter.long2byte(Input);
        this.update(Entrada, 0, Entrada.length);
        return this.digest();
    }

    /**
     * Calcula el HASH de la entrada de un arreglo de int
     *
     * @param Input con un arreglo de int
     * @return HASH del mensaje de entrada
     */
   @Override
    public byte[] Hash(int[] Input) {
        byte[] Entrada;

        this.reset();
        Entrada = Converter.int2byte(Input);
        this.update(Entrada, 0, Entrada.length);
        return this.digest();
    }

   // methods to be implemented by concrete subclasses ------------------------

   @Override
   public abstract Object clone();

   @Override
   public abstract boolean selfTest();

   /**
    * <p>Returns the byte array to use as padding before completing a hash
    * operation.</p>
    *
    * @return the bytes to pad the remaining bytes in the buffer before
    * completing a hash operation.
    */
   protected abstract byte[] padBuffer();

   /**
    * <p>Constructs the result from the contents of the current context.</p>
    *
    * @return the output of the completed hash operation.
    */
   protected abstract byte[] getResult();

   /** Resets the instance for future re-use. */
   protected abstract void resetContext();

   /**
    * <p>The block digest transformation per se.</p>
    *
    * @param in the <i>blockSize</i> long block, as an array of bytes to digest.
    * @param offset the index where the data to digest is located within the
    * input buffer.
    */
   protected abstract void transform(byte[] in, int offset);
}

