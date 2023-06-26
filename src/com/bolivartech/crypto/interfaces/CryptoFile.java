package com.bolivartech.crypto.interfaces;

import com.bolivartech.utils.exception.UtilsException;
import com.bolivartech.utils.files.FileManager;

/**
 * Copyright 2007,2009,2010,2011,2012,2013,2014,2015,2016 BolivarTech C.A.
 *
 *  <p>Homepage: <a href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.</p>
 *  <p>BolivarTech Homepage: <a href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 *   This Interface is the CuaimaCrypt's util for code files.
 *
 *   Define la Interface para realiza la encryptacion y desencryptacion de un archivo basado en un password
 *   de 1 caracter minimos, retornando un archivo encriptado
 *
 * Verison 2.0.0: Se agrego el soporte de algoritmos HASH
 * Version 3.1.0: Se estandarizaron los codigos para los algorimos de Hash
 * 
 * @author Julian Bolivar
 * @version 3.1.0
 */
public interface CryptoFile {
    
    /********** Seleccion de Algoritmos de HASH para el Archivo (bits 0 al 6)***********/
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
    /********  Fin de Seleccion de Algoritmos de HASH para el Archivo *********/
        
    /****** Seleccion de Causas de Error del Algoritmo para las Exepciones *******/
    /** No existe concordancia con el Hash Orignal y el recuperado del mensaje  */
    public final static int ERROR_HASHNOMACH = 1;
    /** La version no coincide con ninguna soportada  */
    public final static int ERROR_VERSION = 2;
    /** Error al tratar de Inicializar el Password  */
    public final static int ERROR_PASSWD = 4;
    /** Error al tratar de abrir el archivo de entrada  */
    public final static int ERROR_OPENINFILE = 5;
    /** Error al tratar de leer el archivo de entrada  */
    public final static int ERROR_NOREADINFILE = 6;
    /** Error al tratar de Decodificar el archivo de entrada  */
    public final static int ERROR_DECODEC = 7;
    /** Error al tratar de borrar el archivo de salida  */
    public final static int ERROR_DELETEOUTFILE = 8;
    /** Error al tratar de crear el archivo de salida  */
    public final static int ERROR_CREATEOUTFILE = 9;
    /** Error al tratar de escribir el archivo de salida  */
    public final static int ERROR_WRITEOUTFILE = 10;
    /** Error al tratar de cerrar el archivo de entrada  */
    public final static int ERROR_CLOSEINFILE = 11;
    /** Error al tratar de cerrar el archivo de salida  */
    public final static int ERROR_CLOSEOUTFILE = 12;
    /** Error al tratar de determinar el tipo de archivo de entrada  */
    public final static int ERROR_INFILETYPE = 13;
    /** Error al tratar de recuperar los parametros de los archivos de entrada, salida y parametros de codificacion  */
    public final static int ERROR_FILEPARAMETERS = 14;
    /** Error al tratar Calcular la posicion del Encabezado del archivo  */
    public final static int ERROR_HEADPOSSITIONERROR = 15;
    /** Error tamaño del archivo de entrada es 0  */
    public final static int ERROR_INPUTFILEZEROSIZE = 16;

    
    /**
     * Establece la clave que utiliza CryptoFile para codificar el texto, la
     * cual debe de tener como minimo un caracter de longitud
     *
     * @param Passw Clave de codificacion
     * @return true si lo logro y false si no
     * @throws UtilsException Excepcion de establecimiento de clave
     */
    public boolean Password(String Passw) throws UtilsException;
    
    /**
     * Realiza la codificacion de un archivo, del que recibe en Input el objeto que lo define, en
     * base a la clave con la cual se inicializo el algoritmo; generando el archivo codificado
     * especificado en Output; si Output es 'null' utiliza el mismo nombre del archivo de entrada
     * y le agrega la extencion .caes
     *
     * Si Output existe es borrado de forma NO SEGURA porque se presupone que si existe es un archivo
     * ya codificado.
     * 
     * En opciones se especifican los parametros de configuracion del algoritmo
     * concatenados con 'or' |
     * 
     * Ejemplo de Como Manejar la excepcion de no poder abrir el archivo de entrada
     *  try {
     *       Salida=CryptoFile.Codec(Entrada,null,CuimaFile.SHA1);
     *   } catch (UtilsException e) {
     *       if(e.getErrorCode()==CuaimaFile.NOOPENINFILE){
     *          System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!");
     *       }
     *   }
     *
     * @param Input  Objeto que define el archivo a codificar
     * @param Output Objeto que define el archivo codificado
     * @param Opciones Parametros de configuracion del codificador
     */
    public void Codec(FileManager Input, FileManager Output, int Opciones);
    
    /**
     * Realiza la decodificacion de un archivo que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo.
     *
     * La salida la coloca en el archivo especificada por Output, si este es 'null' se utiliza
     * la ruta donde esta el archivo original y el nombre original del archivo codificado
     *
     * Ejemplo de Como Manejar la excepcion de no poder abrir el archivo de entrada
     *  try {
     *       Salida=CryptoFile.Codec(Entrada,null,CuimaFile.SHA1);
     *   } catch (UtilsException e) {
     *       if(e.getErrorCode()==CuaimaFile.NOOPENINFILE){
     *          System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!");
     *       }
     *   }
     * 
     * @param Input Archivo de entrada a decodificar
     * @param Output Archivo de salida decodificado
     */
    public void Decodec(FileManager Input, FileManager Output);
    
        /**
     * Retorna el numero de bytes del buffer de lectura para la codificacion del
     * archivo.
     *
     * @return Tamaño del buffer en bytes
     */
    public int getBufferSize();

    /**
     * Establece el numero de bytes para el buffer de lectura para la carga
     * del archivo a codificar.
     * 
     * @param BufferSize (bytes)
     */
    public void setBufferSize(int BufferSize);
    
    /**
     * Retorna el porcentaje de progreso de la operacion de codificacion, el valor
     * esta comprendido entre 0 y 100
     * 
     * NOTA: Un valor de 100 asegura que el proceso fue concluido.
     * 
     * @return Porcentaje de progreso de la operacion 0 &lt;= Salida &lt;= 100
     */
    public int Progress();
    
    /**
     * Retorna true si el proceso fue concluido y false si todavia no se ha finalizado.
     * 
     * @return true el proceso fue concluido y false si todavia no se ha finalizado.
     */
    public boolean isDone();
    
    /**
     * Retorna un manejador de archivo hacia el archivo de salida del
     * algoritmo.
     *
     * NOTA: Si el archivo de Salida no ha sido calculado por el algoritmo
     * retorna NULL.
     *
     * @return Manejador de archivo de Salida.
     */
    public FileManager getOutputFile();

}
