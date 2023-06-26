package com.bolivartech.crypto.interfaces;

import com.bolivartech.utils.exception.UtilsException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Copyright 2007,2009,2010,2011,2012,2013,2014,2015,2016 BolivarTech C.A.
 *
 *  <p>BolivarTech Homepage: <a href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 *   This Class is the CuaimaCrypt's interface for code data Streams.
 *
 *   Define la Interface para realiza la codificacion y decodificacion de un data Stream basado en
 *   un password de 1 caracteres minimos, retornando un Stream encriptada.
 *
 * @author Julian Bolivar
 * @version 1.0.0
 */
public interface CryptoStream {
    
    /********** Seleccion de Algoritmos de HASH para el Mensaje ***********/
    /** No utiliza ningun algoritmo de HASH, el Valor es 0. */
    public final static int NO_HASH = 0;
    /** Utiliza el algoritmo de HASH Whirlpool2003, el Valor es 2. (Por Defecto) */
    public final static int HASH_WHIRLPOOL2003 = 2;
    /** Utiliza el algoritmo de HASH Whirlpool2000, el Valor es 4. */
    public final static int HASH_WHIRLPOOL2000 = 4;
    /** Utiliza el algoritmo de HASH Whirlpool, el Valor es 6.  */
    public final static int HASH_WHIRLPOOL = 6;
    /** Utiliza el algoritmo de HASH SHA0, el Valor es 8.  */
    public final static int HASH_SHA0 = 8;
    /** Utiliza el algoritmo de HASH SHA1, el Valor es 10.  */
    public final static int HASH_SHA1 = 10;
    /** Utiliza el algoritmo de HASH SHA224, el Valor es 12.  */
    public final static int HASH_SHA224 = 12;
    /** Utiliza el algoritmo de HASH SHA256, el Valor es 14.  */
    public final static int HASH_SHA256 = 14;
    /** Utiliza el algoritmo de HASH SHA384, el Valor es 16.  */
    public final static int HASH_SHA384 = 16;
    /** Utiliza el algoritmo de HASH SHA512, el Valor es 18.  */
    public final static int HASH_SHA512 = 18;
    /** Utiliza el algoritmo de HASH TIGER, el Valor es 20.  */
    public final static int HASH_TIGER = 20;
    /** Utiliza el algoritmo de HASH TIGER2, el Valor es 22.  */
    public final static int HASH_TIGER2 = 22;
    /** Utiliza el algoritmo de HASH TIGER128, el Valor es 24.  */
    public final static int HASH_TIGER128 = 24;
    /** Utiliza el algoritmo de HASH TIGER160, el Valor es 26.  */
    public final static int HASH_TIGER160 = 26;
    /** Utiliza el algoritmo de HASH RipeMD128, el Valor es 28.  */
    public final static int HASH_RIPEMD128 = 28;
    /** Utiliza el algoritmo de HASH RipeMD160, el Valor es 30.  */
    public final static int HASH_RIPEMD160 = 30;
    /** Utiliza el algoritmo de HASH MD2, el Valor es 32.  */
    public final static int HASH_MD2 = 32;
    /** Utiliza el algoritmo de HASH MD4, el Valor es 34.  */
    public final static int HASH_MD4 = 34;
    /** Utiliza el algoritmo de HASH MD5, el Valor es 36.  */
    public final static int HASH_MD5 = 36;
    /** Utiliza el algoritmo de HASH HAVAL128, el Valor es 38.  */
    public static final int HASH_HAVAL128 = 38;
    /** Utiliza el algoritmo de HASH HAVAL128, el Valor es 40.  */
    public static final int HASH_HAVAL160 = 40;
    /** Utiliza el algoritmo de HASH HAVAL128, el Valor es 42.  */
    public static final int HASH_HAVAL192 = 42;
    /** Utiliza el algoritmo de HASH HAVAL128, el Valor es 44.  */
    public static final int HASH_HAVAL224 = 44;
    /** Utiliza el algoritmo de HASH HAVAL128, el Valor es 46.  */
    public static final int HASH_HAVAL256 = 46;
    /** Utiliza el algoritmo de HASH HAS160, el Valor es 48.  */
    public final static int HASH_HAS160 = 48;
    /** Utiliza el algoritmo de HASH CRC32, el Valor es 50.  */
    public final static int HASH_CRC32 = 50;
    /** Utiliza el algoritmo de HASH CRC64, el Valor es 52.  */
    public final static int HASH_CRC64 = 52;
   
    /********  Fin de Seleccion de Algoritmos de HASH para el Mensaje *********/
    /****** Seleccion de Causas de Error del Algoritmo para las Exepciones *******/
    /** No existe concordancia con el Hash Orignal y el recuperado del mensaje  */
    public final static int ERROR_HASHNOMACH = -1;
    /** La version no coincide con ninguna soportada  */
    public final static int ERROR_VERSION = -2;
    /** Error al tratar de Inicializar el Password  */
    public final static int ERROR_PASSWD = -3;
    /** Error InputStream is null  */
    public final static int ERROR_NULLINPUTSTREAM = -4;
    /** Error OutputStream is null  */
    public final static int ERROR_NULLOUTPUTSTREAM = -5;
    /** Error de escritura en el OutputStream  */
    public final static int ERROR_WRITEOUTPUTSTREAM = -6;
    /** Error de lectura en el OutputStream  */
    public final static int ERROR_READINPUTSTREAM = -7;
    /** Error de los parametros del Stream  */
    public final static int ERROR_STREAMPARAMETERS = -8;
    /** Error NO se pudo decodificar el password  */
    public final static int ERROR_DECODEC = -9;
    /** Error Proceso Interrumpido  */
    public final static int ERROR_INTERRUPTED = -10;
    
    /**
     * Establece la clave que utiliza CryptoText para codificar el texto, la
     * cual debe de tener como minimo un caracter de longitud
     * 
     * @param Passw Clave a utilizar
     * @return true si lo logro y false si no
     * @throws UtilsException Excepciones de passwords
     */
    public boolean Password(String Passw) throws UtilsException;
    
    /**
     * Realiza la codificacion de una cadena de bytes que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo
     *
     * En opciones se especifican los parametros de configuracion del algoritmo
     * concatenados con 'or' |
     *
     *
     * @param Input Stream de entrada a codificar
     * @param Output Stream de salida codificar
     * @param Opciones Opciones de codificacion
     * @throws UtilsException Excepciones de codificaciones
     */
    public void Codec(InputStream Input, OutputStream Output, int Opciones) throws UtilsException;
    
    /**
     * Realiza la decodificacion de una cadena de bytes que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo.
     *
     * Si no logra decodificarlo retorna una cadena null.
     *
     * Ejemplo de Como Manejar la excepcion de que el Hash No Concuerda
     *  try {
     *       Salida=CryptoBinary.Decodec(Entrada);
     *   } catch (UtilsException e) {
     *       if(e.getErrorCode()==CuaimaBinary.HASHNOMACH){
     *          System.out.println("HASH NO CONCUERDA!!!");
     *       }
     *   }
     *
     * @param Input Stream de Entrada codificada
     * @param Output Stream de Salida decodificar
     * @throws UtilsException Exceciones de decodificacion
     */
    public void Decodec(InputStream Input, OutputStream Output) throws UtilsException;

    /**
     * Retorna TRUE si se concluyo con el proceso de codificacion o FALSE si no.
     * 
     * @return TRUE si se concluto o FASLE si no
     */
    public boolean isDone();
}
