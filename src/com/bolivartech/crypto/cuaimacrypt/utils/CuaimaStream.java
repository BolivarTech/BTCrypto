package com.bolivartech.crypto.cuaimacrypt.utils;

import com.bolivartech.crypto.cuaimacrypt.CuaimaCrypt;
import com.bolivartech.crypto.digest.BaseHash;
import com.bolivartech.crypto.digest.CRC32;
import com.bolivartech.crypto.digest.CRC64;
import com.bolivartech.crypto.digest.Has160;
import com.bolivartech.crypto.digest.Haval;
import com.bolivartech.crypto.digest.MD2;
import com.bolivartech.crypto.digest.MD4;
import com.bolivartech.crypto.digest.MD5;
import com.bolivartech.crypto.digest.RipeMD128;
import com.bolivartech.crypto.digest.RipeMD160;
import com.bolivartech.crypto.digest.Sha0;
import com.bolivartech.crypto.digest.Sha160;
import com.bolivartech.crypto.digest.Sha224;
import com.bolivartech.crypto.digest.Sha256;
import com.bolivartech.crypto.digest.Sha384;
import com.bolivartech.crypto.digest.Sha512;
import com.bolivartech.crypto.digest.Tiger;
import com.bolivartech.crypto.digest.Tiger128;
import com.bolivartech.crypto.digest.Tiger160;
import com.bolivartech.crypto.digest.Tiger2;
import com.bolivartech.crypto.digest.Whirlpool;
import com.bolivartech.crypto.digest.Whirlpool2000;
import com.bolivartech.crypto.digest.Whirlpool2003;
import com.bolivartech.crypto.interfaces.CryptoStream;
import com.bolivartech.utils.array.ArrayUtils;
import com.bolivartech.utils.converters.Converter;
import com.bolivartech.utils.exception.UtilsException;
import com.bolivartech.utils.log.LoggerManager;
import com.bolivartech.utils.random.MersenneTwisterPlus;
import com.bolivartech.utils.btthreads.annotations.GuardedBy;
import com.bolivartech.utils.btthreads.annotations.ThreadSafe;
import com.bolivartech.utils.environment.EnvironmentUtils;
import com.bolivartech.utils.log.LoggerFormatter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * <p>
 * Copyright 2007,2009,2010,2011,2012,2013,2014,2015,2016 BolivarTech INC</p>
 *
 * <p>
 * Homepage:
 * <a href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.</p>
 * <p>
 * BolivarTech Homepage:
 * <a href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 * <p>
 * This Class is the CuaimaCrypt's util for Code and Decode Stream data.</p>
 *
 * <p>
 * Realiza la codificacion y decodificacion de un Stream de datos basado en un
 * password de 1 caracteres minimos, retornando un Stream de datos
 * encriptados.</p>
 *
 * <ul>
 * <li>Class ID: "TR74ID2"</li>
 * <li>Loc: 000-044</li>
 * <ul>
 *
 * @author Julian Bolivar
 * @since 2016 | 2016-03-25
 * @version 1.0.1
 *
 * <p>
 * Change Log:
 * </p>
 * <ul>
 * <li>v1.0.0 (2016-01-31) Version Inicial.</li>
 * <li>v1.0.1 (2016-03-25) Se agrego el codigo de localizacion para la excepcion
 * y bitacoras.</li>
 * </ul>
 */
@ThreadSafe
public class CuaimaStream implements CryptoStream, Runnable {

    // Codigo de identificacion de la clase
    private static final String CLASSID = "TR74ID2";

    // TimeOut de espera en milisegundos
    private final static long TIMEOUT = 1500;

    // Tamaño maximo del Buffer
    private static final int MAXBUFFERSIZE = 52428800;  // 50 MB

    // Los lock para el manejo de concurrencia
    private final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();

    // Manejador de Bitacoras
    private LoggerFormatter BTLogF;

    @GuardedBy("CCPT")
    private final CuaimaCrypt CCPT;
    @GuardedBy("rwl")
    private int PasswdLength;
    @GuardedBy("rwl")
    private int BufferSize; // Tamaño del buffer de lectura en bytes
    @GuardedBy("StreamParameters")
    private StreamOperationParameters StreamParameters;
    // Hebra de ejecucion de la codificacion o Decodificacion
    @GuardedBy("rwl")
    private Thread Ejecutor = null;
    // TRUE si es para codificar y FALSE si es para Decodificar
    private boolean Coding = true;
    @GuardedBy("rwl")
    int ErrorCode = 0;  // Codigo de Error de la Ejecicion
    // Bandera para indicar is el proceso se finalizo        
    @GuardedBy("rwl")
    boolean isFinished;
    // Bandera para indicar is el proceso continua o para interrumpirlo
    @GuardedBy("rwl")
    boolean Continue;

    /**
     * Version del algoritmo CuaimaCryptFile (NOTA: Maximo hasta 255 porque son
     * solo 8 bits)
     */
    private final static short VERSION = 1;

    /**
     * Mascara para recuperar el valor del algoritmo de HASH
     */
    private final static int HASHMASK = 62;

    /**
     * La cantidad de bloques es menor a 2 para inicializar el algoritmo
     */
    public final static int ERROR_NUMBLCK = 3;

    /**
     * Constructor por defecto de CuaimaFile, utilizando 9 bloques de RakeCodecs
     *
     * @param Log Apuntador al manejador de Logs del sistema, si es "null" se
     * usa el estandar de Java
     */
    public CuaimaStream(LoggerManager Log) {

        PasswdLength = -1;
        BufferSize = MAXBUFFERSIZE;
        CCPT = new CuaimaCrypt();
        this.BTLogF = LoggerFormatter.getInstance(Log); // Manejador de Logs
    }

    /**
     * Constructor con inicializacion del numero de bloques de RakeCodecs a
     * utilizar por CuaimaCrypt.
     *
     * El minimo numero de bloques de RakeCodecs es 2.
     *
     * @param NumBlocks Numero de bloques a usar.
     * @param Log Apuntador al manejador de Logs del sistema, si es "null" se
     * usa el estandar de Java
     * @throws UtilsException
     */
    public CuaimaStream(int NumBlocks, LoggerManager Log) throws UtilsException {

        PasswdLength = -1;
        this.BTLogF = LoggerFormatter.getInstance(Log); // Manejador de Logs
        if (NumBlocks >= 2) {
            BufferSize = MAXBUFFERSIZE;
            CCPT = new CuaimaCrypt(NumBlocks);
        } else {
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaFile, la cantidad de bloques es menor a 2", ERROR_NUMBLCK, CuaimaStream.CLASSID + "000");
        }
    }

    /**
     * Constructor con inicializacion del password de CuaimaText, utilizando 9
     * bloques de RakeCodecs
     *
     * @param Password Password a usar para inicializar el algoritmo
     * @param Log Apuntador al manejador de Logs del sistema, si es "null" se
     * usa el estandar de Java
     * @throws UtilsException
     */
    public CuaimaStream(String Password, LoggerManager Log) throws UtilsException {

        this.BTLogF = LoggerFormatter.getInstance(Log); // Manejador de Logs
        BufferSize = MAXBUFFERSIZE;
        CCPT = new CuaimaCrypt();
        if (CCPT.Password(Password) != 0) {
            PasswdLength = -1;
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaFile, falla al inicializar el Password", ERROR_PASSWD, CuaimaStream.CLASSID + "001");
        } else {
            PasswdLength = Password.length();
        }
    }

    /**
     * Constructor con inicializacion del password de CuaimaText, utilizando la
     * cantidad de bloques de RakeCodecs especificada en NumBlocks.
     *
     * NOTA: el numero minimo de loques es 2.
     *
     * @param Password Password a usar para inicializar el algoritmo
     * @param NumBlocks Numero de bloques a utilizar, minimo 2
     * @param Log Apuntador al manejador de Logs del sistema, si es "null" se
     * usa el estandar de Java
     * @throws UtilsException
     */
    public CuaimaStream(String Password, int NumBlocks, LoggerManager Log) throws UtilsException {

        this.BTLogF = LoggerFormatter.getInstance(Log); // Manejador de Logs
        BufferSize = MAXBUFFERSIZE;
        if (NumBlocks >= 2) {
            CCPT = new CuaimaCrypt(NumBlocks);
        } else {
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaFile, la cantidad de bloques es menor a 2", ERROR_NUMBLCK, CuaimaStream.CLASSID + "002");
        }
        if (CCPT.Password(Password) != 0) {
            PasswdLength = -1;
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaFile, falla al inicializar con el Password", ERROR_PASSWD, CuaimaStream.CLASSID + "003");
        } else {
            PasswdLength = Password.length();
        }
    }

    /**
     * Retorna el identificador de la Clase
     * 
     * @return Identificador de la clase
     */
    public static String getCLASSID() {
        return CLASSID;
    }
    
    /**
     * Establece la clave que utiliza CuaimaText para codificar el texto, la
     * cual debe de tener como minimo un caracter de longitud
     *
     * @param Passw
     * @return true si lo logro y false si no
     * @throws UtilsException
     */
    @Override
    public boolean Password(String Passw) throws UtilsException {
        boolean salida = false;

        this.rwl.writeLock().lock();
        try {
            if ((this.Ejecutor == null) || (this.Ejecutor.getState() == Thread.State.TERMINATED)) {
                PasswdLength = -1;
                if (CCPT != null) {
                    synchronized (CCPT) {
                        if (CCPT.Password(Passw) != 0) {
                            throw new UtilsException("ERROR: NO se pudo inicializar la clave en CuaimaFile", ERROR_PASSWD, CuaimaStream.CLASSID + "004");
                        } else {
                            PasswdLength = Passw.length();
                            salida = true;
                        }
                    }
                }
            }
        } finally {
            this.rwl.writeLock().unlock();
        }
        return salida;
    }

    /**
     * Reinicia los ShiftCodecs a las semillas iniciales de los mismos
     */
    public void Reset() {

        this.rwl.readLock().lock();
        try {
            if ((this.Ejecutor == null) || (this.Ejecutor.getState() == Thread.State.TERMINATED)) {
                if (PasswdLength > 0) {
                    if (CCPT != null) {
                        synchronized (CCPT) {
                            CCPT.Reset();
                        }
                    }
                }
            }
        } finally {
            this.rwl.readLock().unlock();
        }
    }

    /**
     * Realiza la cancelacion del proceso de codificacion
     */
    public void Cancel() {

        this.rwl.writeLock().lock();
        try {
            this.Continue = false;
        } finally {
            this.rwl.writeLock().unlock();
        }
    }

    /**
     * Retorna el numero de bytes del buffer de lectura para la codificacion del
     * archivo.
     *
     * @return Tamaño del buffer en bytes
     */
    public int getBufferSize() {
        int Result;

        this.rwl.readLock().lock();
        try {
            Result = BufferSize;
        } finally {
            this.rwl.readLock().unlock();
        }
        return Result;
    }

    /**
     * Establece el numero de bytes para el buffer de lectura para la carga del
     * archivo a codificar. El buffer siempre sera multipo de 16 bytes.
     *
     * El buffer minimo sera de 16 bytes que es equivalente a 128 bits
     *
     * @param BufferSize (bytes)
     */
    public void setBufferSize(int BufferSize) {
        int i;

        if (BufferSize >= 128) {
            i = BufferSize % 16;
            this.rwl.writeLock().lock();
            try {
                this.BufferSize = (i > 0 ? BufferSize - i : BufferSize);
            } finally {
                this.rwl.writeLock().unlock();
            }
        }
    }

    /**
     * Realiza la defragmentacion del buffer en memoria, moviento la data que
     * quedo remanente al principio del buffer. Retorna la primera posicion de
     * dato libre en el buffer defragmentado o -1 si ocurrio algun error.
     *
     * @param Buffer Buffer a Defragmentar
     * @param DataRemain Cantidad de data remanente que quedo en el buffer sin
     * procesar
     * @param DataLength Longitud total de la data en el buffer.
     * @return Primera posicion de dato libre en el buffer defragmentado o -1 si
     * error.
     */
    private int defragBuffer(byte[] Buffer, int DataRemain, int DataLength) {
        int Result = -1;
        int i, j;

        if ((DataRemain <= Buffer.length) && (DataLength <= Buffer.length) && (DataRemain <= DataLength)) {
            j = DataLength - DataRemain;
            for (i = 0; i < DataRemain; i++) {
                Buffer[i] = Buffer[j + i];
            }
            Result = i;
        }
        return Result;
    }

    /**
     * Realiza la codificacion de un InputStream y el resultado es enviado a un
     * OutputStream.
     *
     * @throws UtilsException
     */
    private void PrivCodec() throws UtilsException {
        MersenneTwisterPlus Rand;
        int i, j;
        int NumBytesReads;
        byte InputBuffer[];
        byte SubInputBuffer[];
        byte OutputBuffer[];
        long Header[];
        long Tail[];
        long CBuffer[];
        int ReadPos;
        int DataLength;
        int DataRemain;
        int HashType;
        BaseHash Hash;
        boolean LContinue;
        InputStream Input;
        OutputStream Output;
        int Opciones;

        // Verifica si el algoritmo fue inicializado
        if (StreamParameters != null) {
            Input = StreamParameters.getInput();
            if (Input != null) {
                Output = StreamParameters.getOutput();
                if (Output != null) {
                    Opciones = StreamParameters.getOpciones();
                    if (PasswdLength > 0) {
                        // Inicializa el generador de numeros aleatorios
                        Rand = new MersenneTwisterPlus();
                        // Reinicializa el algoritmo en base a la clave con la cual se configuro
                        synchronized (CCPT) {
                            CCPT.Reset();
                        }
                        // Inicializa el Algoritmo de HASH
                        HashType = Opciones & HASHMASK;
                        switch (HashType) {
                            case HASH_WHIRLPOOL2003:
                                Hash = new Whirlpool2003();
                                break;
                            case HASH_WHIRLPOOL2000:
                                Hash = new Whirlpool2000();
                                break;
                            case HASH_WHIRLPOOL:
                                Hash = new Whirlpool();
                                break;
                            case HASH_SHA0:
                                Hash = new Sha0();
                                break;
                            case HASH_SHA1:
                                Hash = new Sha160();
                                break;
                            case HASH_SHA224:
                                Hash = new Sha224();
                                break;
                            case HASH_SHA256:
                                Hash = new Sha256();
                                break;
                            case HASH_SHA384:
                                Hash = new Sha384();
                                break;
                            case HASH_SHA512:
                                Hash = new Sha512();
                                break;
                            case HASH_TIGER:
                                Hash = new Tiger();
                                break;
                            case HASH_TIGER2:
                                Hash = new Tiger2();
                                break;
                            case HASH_TIGER128:
                                Hash = new Tiger128();
                                break;
                            case HASH_TIGER160:
                                Hash = new Tiger160();
                                break;
                            case HASH_RIPEMD128:
                                Hash = new RipeMD128();
                                break;
                            case HASH_RIPEMD160:
                                Hash = new RipeMD160();
                                break;
                            case HASH_MD2:
                                Hash = new MD2();
                                break;
                            case HASH_MD4:
                                Hash = new MD4();
                                break;
                            case HASH_MD5:
                                Hash = new MD5();
                                break;
                            case HASH_HAVAL128:
                                Hash = new Haval(Haval.HAVAL_128_BIT);
                                break;
                            case HASH_HAVAL160:
                                Hash = new Haval(Haval.HAVAL_160_BIT);
                                break;
                            case HASH_HAVAL192:
                                Hash = new Haval(Haval.HAVAL_192_BIT);
                                break;
                            case HASH_HAVAL224:
                                Hash = new Haval(Haval.HAVAL_224_BIT);
                                break;
                            case HASH_HAVAL256:
                                Hash = new Haval(Haval.HAVAL_256_BIT);
                                break;
                            case HASH_HAS160:
                                Hash = new Has160();
                                break;
                            case HASH_CRC32:
                                Hash = new CRC32();
                                break;
                            case HASH_CRC64:
                                Hash = new CRC64();
                                break;
                            case NO_HASH:
                                Hash = null;
                                break;
                            default:
                                Hash = new Whirlpool2003();
                        }
                        if (Hash != null) {
                            Hash.reset();
                        }
                        // Genera el Encabezado del stream
                        Header = new long[4];
                        Header[0] = (Rand.nextLong() << 32) | (Converter.byte2long(new String("CCPTTPCC").getBytes(StandardCharsets.US_ASCII))[0] >>> 32);  // BYTES de OFUSCACION
                        Header[1] = (Converter.byte2long(new String("CCPTTPCC").getBytes(StandardCharsets.US_ASCII))[0] << 32) | (Rand.nextLong() >>> 32);  // BYTES de OFUSCACION
                        Header[2] = Rand.nextLong();  // BYTES de OFUSCACION
                        Header[3] = Rand.nextLong() << 32;  // BYTES de OFUSCACION
                        Header[3] |= HashType << 26;  // Hash usado en el mensaje
                        Header[3] |= VERSION & 0xFF;    // VERSION DE CUAIMABINARY
                        // Genera la cola de cierre del stream
                        Tail = new long[2];
                        Tail[0] = (Rand.nextLong() << 32) | (Converter.byte2long(new String("CCPTTPCC").getBytes(StandardCharsets.US_ASCII))[0] >>> 32);  // BYTES de OFUSCACION
                        Tail[1] = (Converter.byte2long(new String("CCPTTPCC").getBytes(StandardCharsets.US_ASCII))[0] << 32) | (Rand.nextLong() >>> 32);  // BYTES de OFUSCACION
                        // Codifica el Encabezado del archivo
                        CBuffer = new long[2];
                        for (i = 0; i < Header.length; i += 2) {
                            CBuffer[0] = Header[i];
                            CBuffer[1] = Header[i + 1];
                            synchronized (CCPT) {
                                CCPT.Codec(CBuffer);
                            }
                            Header[i] = CBuffer[0];
                            Header[i + 1] = CBuffer[1];
                        }
                        // Envia el encabezado por el OutputStream
                        OutputBuffer = Converter.long2byte(Header);
                        try {
                            Output.write(OutputBuffer);
                        } catch (IOException ex) {
                            // Error de lectura del archivo de entrada
                            throw new UtilsException("ERROR: Can't write to OutputStream to send Header [" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "005");
                        }
                        // Codifica el InputStream
                        this.rwl.readLock().lock();
                        try {
                            InputBuffer = new byte[this.BufferSize]; // Buffer de Entrada
                            LContinue = this.Continue;
                        } finally {
                            this.rwl.readLock().unlock();
                        }
                        SubInputBuffer = new byte[16];
                        NumBytesReads = 0;
                        ReadPos = 0;
                        // Lectura del InputStream
                        while ((NumBytesReads >= 0) && (LContinue)) {
                            try {
                                DataLength = InputBuffer.length - ReadPos;
                                NumBytesReads = Input.read(InputBuffer, ReadPos, DataLength);
                                if (NumBytesReads < 0) {
                                    DataLength = ReadPos;
                                } else {
                                    DataLength = ReadPos + NumBytesReads;
                                }
                            } catch (IOException ex) {
                                // Error de lectura del archivo de entrada
                                throw new UtilsException("ERROR: Can't read from InputStream[" + ex.getMessage() + "]", ERROR_READINPUTSTREAM, CuaimaStream.CLASSID + "006");
                            }
                            // Verifica si se leyeron datos
                            if (NumBytesReads > 0) {
                                // Actualiza el Hash
                                if (Hash != null) {
                                    Hash.update(InputBuffer, ReadPos, NumBytesReads);
                                }
                                // Realiza la codificacion del buffer leido desde el InputStream
                                DataRemain = DataLength % 16;
                                for (i = 0; i < (DataLength - DataRemain); i += 16) {
                                    for (j = 0; j < 16; j++) {
                                        SubInputBuffer[j] = InputBuffer[i + j];
                                    }
                                    // Codifica el bloque de 128 bits
                                    CBuffer = Converter.byte2long(SubInputBuffer);
                                    synchronized (CCPT) {
                                        CCPT.Codec(CBuffer);
                                    }
                                    SubInputBuffer = Converter.long2byte(CBuffer);
                                    for (j = 0; j < 16; j++) {
                                        InputBuffer[i + j] = SubInputBuffer[j];
                                    }
                                }
                                // Escribe la data codificada en el OutStream
                                try {
                                    // Escribe el bloque de datos
                                    Output.write(InputBuffer, 0, DataLength - DataRemain);
                                } catch (IOException ex) {
                                    // Error de escritura del OutStream
                                    throw new UtilsException("ERROR: Can't write in the OutStream[" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "007");
                                }
                                // Defragmenta el buffer moviendo al principio la data no codificada
                                ReadPos = this.defragBuffer(InputBuffer, DataRemain, DataLength);
                            }
                            // Verifica si se continua con el proceso de condificacion
                            this.rwl.readLock().lock();
                            try {
                                LContinue = this.Continue;
                            } finally {
                                this.rwl.readLock().unlock();
                            }
                        }
                        // Se verifica si el proceso no fue interrumpido y se termina de procesar lo que queda en el buffer
                        if (LContinue) {
                            OutputBuffer = Converter.long2byte(Tail);
                            if (Hash != null) {
                                DataLength = ReadPos + Hash.hashSize() + OutputBuffer.length;
                            } else {
                                DataLength = ReadPos + OutputBuffer.length;
                            }
                            // Verifca que sera multipo de 16 el buffer resultante
                            DataRemain = ((DataLength % 16) != 0 ? 16 - (DataLength % 16) : 0);
                            if (DataRemain > 0) {
                                DataLength += DataRemain;
                            }
                            if (DataLength > InputBuffer.length) {
                                // Realiza el redimensionamiento del buffer para incluir el Hash (si existe) y la cola del CuaimaStream
                                InputBuffer = (byte[]) ArrayUtils.resizeArray(InputBuffer, DataLength);
                            }
                            // Se agrega el Hash si hace falta
                            if (Hash != null) {
                                ArrayUtils.arrayCopy(Hash.digest(), 0, InputBuffer, ReadPos, Hash.hashSize());
                                ReadPos += Hash.hashSize();
                            }
                            // Agrega la cola
                            ArrayUtils.arrayCopy(OutputBuffer, 0, InputBuffer, ReadPos, OutputBuffer.length);
                            ReadPos += OutputBuffer.length;
                            // Completa cualquier byte vacio que quede al final del buffer con numeros random
                            while (ReadPos < DataLength) {
                                InputBuffer[ReadPos] = Rand.nextByte();
                                ReadPos++;
                            }
                            // Realiza la codificacion del buffer de datos
                            for (i = 0; i < DataLength; i += 16) {
                                for (j = 0; j < 16; j++) {
                                    SubInputBuffer[j] = InputBuffer[i + j];
                                }
                                // Codifica el bloque de 128 bits
                                CBuffer = Converter.byte2long(SubInputBuffer);
                                synchronized (CCPT) {
                                    CCPT.Codec(CBuffer);
                                }
                                SubInputBuffer = Converter.long2byte(CBuffer);
                                for (j = 0; j < 16; j++) {
                                    InputBuffer[i + j] = SubInputBuffer[j];
                                }
                            }
                            // Escribe la data codificada en el OutStream
                            try {
                                // Escribe el bloque de datos
                                Output.write(InputBuffer, 0, DataLength);
                            } catch (IOException ex) {
                                // Error de escritura del OutStream
                                throw new UtilsException("ERROR: Can't write in the OutStream to send the last packet[" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "008");
                            }
                        } else {
                            // Codifica y envia la cola del CuamiaStream para finalizar el protocolo 
                            // pero sin enviar el hash ni la data remanente en el buffer
                            for (i = 0; i < Tail.length; i += 2) {
                                CBuffer[0] = Tail[i];
                                CBuffer[1] = Tail[i + 1];
                                synchronized (CCPT) {
                                    CCPT.Codec(CBuffer);
                                }
                                Tail[i] = CBuffer[0];
                                Tail[i + 1] = CBuffer[1];
                            }
                            // Envia la cola por el OutputStream
                            OutputBuffer = Converter.long2byte(Tail);
                            try {
                                Output.write(OutputBuffer);
                            } catch (IOException ex) {
                                // Error de lectura del archivo de entrada
                                throw new UtilsException("ERROR: Can't write to OutputStream to send Tail [" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "009");
                            }
                        }
                        try {
                            Input.close();
                            Output.flush();
                            Output.close();
                        } catch (IOException ex) {
                            // Error al vaciar el OutputStream
                            throw new UtilsException("ERROR: Can't Flush OutputStream[" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "010");
                        }
                    } else {
                        throw new UtilsException("ERROR: Password NOT defined to codec Stream", ERROR_PASSWD, CuaimaStream.CLASSID + "011");
                    }
                } else {
                    throw new UtilsException("ERROR: OutputStream is NULL", ERROR_NULLOUTPUTSTREAM, CuaimaStream.CLASSID + "012");
                }
            } else {
                throw new UtilsException("ERROR: InputStream is NULL", ERROR_NULLINPUTSTREAM, CuaimaStream.CLASSID + "013");
            }
        } else {
            throw new UtilsException("ERROR: Codification Parameters NOT Defined", ERROR_STREAMPARAMETERS, CuaimaStream.CLASSID + "014");
        }
    }

    /**
     * Busca la cola de 8 bytes en el buffer a partir de la posicion 'readPos'
     * hasta la posicion 'endDataPos'. Retorna la posicion donde empieza la cola
     * o -1 si no la consiguio
     *
     * @param buffer Buffer donde buscar la cosa
     * @param readPos Posicion inicial donde buscar
     * @param endDataPos posicion final de busqueda
     * @return Posicion de la cola o -1 si no la consiguio.
     */
    private int tailFinder(byte[] buffer, int readPos, int endDataPos) {
        int Pos = -1;
        int Diff, i, TailLength;
        String Tail;
        StringBuffer TailMark;

        TailMark = new StringBuffer("CCPTTPCC");
        TailLength = TailMark.toString().getBytes(StandardCharsets.US_ASCII).length;
        Diff = endDataPos - readPos;
        if (Diff >= TailLength) {
            Diff = endDataPos - TailLength;
            for (i = readPos; i < Diff; i++) {
                Tail = new String((byte[]) ArrayUtils.subArray(buffer, i, TailLength), StandardCharsets.US_ASCII);
                if (Tail.contentEquals(TailMark)) {
                    Pos = i - 4;
                    if (Pos < 0) {
                        Pos = 0;
                    }
                    i = endDataPos;
                }
            }
        }
        return Pos;
    }

    /**
     * Realiza la decodificacion de un archivo que recibe en Input en base a la
     * clave con la cual se inicializo el algoritmo.
     *
     * La salida la coloca en el archivo especificada por Output, si este es
     * 'null' se utiliza la ruta donde esta el archivo original y el nombre
     * original del archivo codificado
     *
     * Ejemplo de Como Manejar la excepcion de no poder abrir el archivo de
     * entrada try { Salida=CuaimaFile.Codec(Entrada,null,CuimaFile.SHA1); }
     * catch (UtilsException e) { if(e.getErrorCode()==CuaimaFile.NOOPENINFILE){
     * System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!"); } }
     *
     * @throws UtilsException
     */
    private void PrivDecodec() throws UtilsException {
        int i, j;
        int NumBytesReads;
        long Header[], HTemp[];
        long DcBuffer[];
        String HeaderDec;
        byte InputBuffer[];
        byte SubInputBuffer[];
        int HashType;
        BaseHash Hash;
        byte[] OrgDigest = null;
        byte[] NewDigest = null;
        int Version;
        InputStream Input;
        OutputStream Output;
        boolean LContinue;
        int ReadPos;
        int DataLength;
        int DataRemain;
        int TailPos;

        // Verifica si el algoritmo fue inicializado
        if (StreamParameters != null) {
            Input = StreamParameters.getInput();
            if (Input != null) {
                Output = StreamParameters.getOutput();
                if (Output != null) {
                    if (PasswdLength > 0) {
                        // Reinicializa el algoritmo en base a la clave con la cual se configuro
                        synchronized (CCPT) {
                            CCPT.Reset();
                        }
                        // Trata de recuperar el encabezado
                        InputBuffer = new byte[32]; // Buffer de Entrada
                        ReadPos = 0;
                        do {
                            try {
                                DataLength = InputBuffer.length - ReadPos;
                                NumBytesReads = Input.read(InputBuffer, ReadPos, DataLength);
                                if (NumBytesReads < 0) {
                                    DataLength = ReadPos;
                                } else {
                                    DataLength = ReadPos + NumBytesReads;
                                }
                                ReadPos += NumBytesReads;
                            } catch (IOException ex) {
                                // Error de lectura del archivo de entrada
                                throw new UtilsException("ERROR: Can't read from InputStream[" + ex.getMessage() + "]", ERROR_READINPUTSTREAM, CuaimaStream.CLASSID + "015");
                            } finally {
                                // Verifica si se continua con el proceso de condificacion
                                this.rwl.readLock().lock();
                                try {
                                    LContinue = this.Continue;
                                } finally {
                                    this.rwl.readLock().unlock();
                                }
                            }
                        } while ((ReadPos < InputBuffer.length) && (LContinue));
                        if (LContinue) {
                            if (ReadPos == InputBuffer.length) {
                                Header = Converter.byte2long(InputBuffer);
                            } else {
                                throw new UtilsException("ERROR: Can't read header from InputStream", ERROR_READINPUTSTREAM, CuaimaStream.CLASSID + "016");
                            }
                            // Decodifica el Encabezado del archivo
                            DcBuffer = new long[2];
                            for (i = 0; i < Header.length; i += 2) {
                                DcBuffer[0] = Header[i];
                                DcBuffer[1] = Header[i + 1];
                                synchronized (CCPT) {
                                    CCPT.Decodec(DcBuffer);
                                }
                                Header[i] = DcBuffer[0];
                                Header[i + 1] = DcBuffer[1];
                            }
                            // Trata de Recuperar Informacion del Encabezado
                            HTemp = new long[1];
                            HTemp[0] = (Header[0] << 32) | (Header[1] >>> 32);
                            HeaderDec = new String(Converter.long2byte(HTemp), StandardCharsets.US_ASCII);
                            // Verifica si se pudo recuperar la informacion del encabezado
                            if (HeaderDec.contentEquals(new StringBuffer("CCPTTPCC"))) {
                                // Verifica la Version
                                Version = (int) (Header[3] & 0xFFL);
                                if (Version == (VERSION & 0xFF)) {
                                    // Recupera el Tipo de Hash utilizado
                                    HashType = ((int) (Header[3] >>> 26)) & HASHMASK;
                                    switch (HashType) {
                                        case HASH_WHIRLPOOL2003:
                                            Hash = new Whirlpool2003();
                                            break;
                                        case HASH_WHIRLPOOL2000:
                                            Hash = new Whirlpool2000();
                                            break;
                                        case HASH_WHIRLPOOL:
                                            Hash = new Whirlpool();
                                            break;
                                        case HASH_SHA0:
                                            Hash = new Sha0();
                                            break;
                                        case HASH_SHA1:
                                            Hash = new Sha160();
                                            break;
                                        case HASH_SHA224:
                                            Hash = new Sha224();
                                            break;
                                        case HASH_SHA256:
                                            Hash = new Sha256();
                                            break;
                                        case HASH_SHA384:
                                            Hash = new Sha384();
                                            break;
                                        case HASH_SHA512:
                                            Hash = new Sha512();
                                            break;
                                        case HASH_TIGER:
                                            Hash = new Tiger();
                                            break;
                                        case HASH_TIGER2:
                                            Hash = new Tiger2();
                                            break;
                                        case HASH_TIGER128:
                                            Hash = new Tiger128();
                                            break;
                                        case HASH_TIGER160:
                                            Hash = new Tiger160();
                                            break;
                                        case HASH_RIPEMD128:
                                            Hash = new RipeMD128();
                                            break;
                                        case HASH_RIPEMD160:
                                            Hash = new RipeMD160();
                                            break;
                                        case HASH_MD2:
                                            Hash = new MD2();
                                            break;
                                        case HASH_MD4:
                                            Hash = new MD4();
                                            break;
                                        case HASH_MD5:
                                            Hash = new MD5();
                                            break;
                                        case HASH_HAVAL128:
                                            Hash = new Haval(Haval.HAVAL_128_BIT);
                                            break;
                                        case HASH_HAVAL160:
                                            Hash = new Haval(Haval.HAVAL_160_BIT);
                                            break;
                                        case HASH_HAVAL192:
                                            Hash = new Haval(Haval.HAVAL_192_BIT);
                                            break;
                                        case HASH_HAVAL224:
                                            Hash = new Haval(Haval.HAVAL_224_BIT);
                                            break;
                                        case HASH_HAVAL256:
                                            Hash = new Haval(Haval.HAVAL_256_BIT);
                                            break;
                                        case HASH_HAS160:
                                            Hash = new Has160();
                                            break;
                                        case HASH_CRC32:
                                            Hash = new CRC32();
                                            break;
                                        case HASH_CRC64:
                                            Hash = new CRC64();
                                            break;
                                        case NO_HASH:
                                            Hash = null;
                                            break;
                                        default:
                                            Hash = new Whirlpool2003();
                                    }
                                    if (Hash != null) {
                                        Hash.reset();
                                    }
                                    // Decodifica el InputStream
                                    this.rwl.readLock().lock();
                                    try {
                                        InputBuffer = new byte[this.BufferSize]; // Buffer de Entrada
                                        LContinue = this.Continue;
                                    } finally {
                                        this.rwl.readLock().unlock();
                                    }
                                    SubInputBuffer = new byte[16];
                                    NumBytesReads = 0;
                                    ReadPos = 0;
                                    TailPos = -1;
                                    // Lectura del InputStream
                                    while ((NumBytesReads >= 0) && (LContinue) && (TailPos < 0)) {
                                        try {
                                            DataLength = InputBuffer.length - ReadPos;
                                            NumBytesReads = Input.read(InputBuffer, ReadPos, DataLength);
                                            if (NumBytesReads < 0) {
                                                DataLength = ReadPos;
                                            } else {
                                                DataLength = ReadPos + NumBytesReads;
                                            }
                                        } catch (IOException ex) {
                                            // Error de lectura del archivo de entrada
                                            throw new UtilsException("ERROR: Can't read from InputStream[" + ex.getMessage() + "]", ERROR_READINPUTSTREAM, CuaimaStream.CLASSID + "017");
                                        }
                                        // Verifica si se leyeron datos
                                        if (NumBytesReads > 0) {
                                            // Realiza la decodificacion del buffer leido desde el InputStream
                                            DataRemain = DataLength % 16;
                                            for (i = ReadPos; i < (DataLength - DataRemain); i += 16) {
                                                for (j = 0; j < 16; j++) {
                                                    SubInputBuffer[j] = InputBuffer[i + j];
                                                }
                                                // Codifica el bloque de 128 bits
                                                DcBuffer = Converter.byte2long(SubInputBuffer);
                                                synchronized (CCPT) {
                                                    CCPT.Decodec(DcBuffer);
                                                }
                                                SubInputBuffer = Converter.long2byte(DcBuffer);
                                                for (j = 0; j < 16; j++) {
                                                    InputBuffer[i + j] = SubInputBuffer[j];
                                                }
                                            }
                                            TailPos = this.tailFinder(InputBuffer, 0, DataLength - DataRemain);
                                            if (TailPos < 0) {
                                                // Actualiza el Hash
                                                if (Hash != null) {
                                                    DataRemain = (DataLength - DataRemain) - Hash.hashSize();
                                                    DataRemain = (DataRemain > 0 ? DataRemain : 0);
                                                    Hash.update(InputBuffer, 0, DataRemain);
                                                } else {
                                                    DataRemain = (DataLength - DataRemain);
                                                    DataRemain = (DataRemain > 0 ? DataRemain : 0);
                                                }
                                                // Escribe la data decodificados en el OutStream
                                                try {
                                                    // Escribe el bloque de datos
                                                    Output.write(InputBuffer, 0, DataRemain);
                                                } catch (IOException ex) {
                                                    // Error de escritura del OutStream
                                                    throw new UtilsException("ERROR: Can't write in the OutStream[" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "018");
                                                }
                                                // Defragmenta el buffer moviendo al principio la data no codificada
                                                ReadPos = this.defragBuffer(InputBuffer, (DataLength - DataRemain), DataLength);
                                            }
                                        }
                                        // Verifica si se continua con el proceso de condificacion
                                        this.rwl.readLock().lock();
                                        try {
                                            LContinue = this.Continue;
                                        } finally {
                                            this.rwl.readLock().unlock();
                                        }
                                    }
                                    if (TailPos >= 0) {
                                        // Se encontro la cola
                                        if (Hash != null) {
                                            TailPos -= Hash.hashSize();
                                            Hash.update(InputBuffer, 0, TailPos);
                                            OrgDigest = (byte[]) ArrayUtils.subArray(InputBuffer, TailPos, Hash.hashSize());
                                            NewDigest = Hash.digest();
                                            if (!Arrays.equals(OrgDigest, NewDigest)) {
                                                throw new UtilsException("ERROR: HASH NO COINCIDEN", ERROR_HASHNOMACH, CuaimaStream.CLASSID + "019");
                                            }
                                        }
                                        // Escribe la data decodificados en el OutStream
                                        try {
                                            // Escribe el bloque de datos
                                            Output.write(InputBuffer, 0, TailPos);
                                        } catch (IOException ex) {
                                            // Error de escritura del OutStream
                                            throw new UtilsException("ERROR: Can't write in the OutStream[" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "020");
                                        }
                                    } else if (!LContinue) {
                                        throw new UtilsException("WARING: Decode interrupted", ERROR_INTERRUPTED, CuaimaStream.CLASSID + "021");
                                    } else {
                                        throw new UtilsException("ERROR: Input Stream Early End Of Data", ERROR_READINPUTSTREAM, CuaimaStream.CLASSID + "022");
                                    }
                                    try {
                                        Input.close();
                                        Output.flush();
                                        Output.close();
                                    } catch (IOException ex) {
                                        // Error al vaciar el OutputStream
                                        throw new UtilsException("ERROR: Can't Flush OutputStream[" + ex.getMessage() + "]", ERROR_WRITEOUTPUTSTREAM, CuaimaStream.CLASSID + "023");
                                    }
                                }
                            } else {
                                throw new UtilsException("ERROR: NO se pudo Decodificar el Stream", ERROR_DECODEC, CuaimaStream.CLASSID + "024");
                            }
                        }
                    } else {
                        throw new UtilsException("ERROR: Password NOT defined to decodec Stream", ERROR_PASSWD, CuaimaStream.CLASSID + "025");
                    }
                } else {
                    throw new UtilsException("ERROR: OutputStream is NULL", ERROR_NULLOUTPUTSTREAM, CuaimaStream.CLASSID + "026");
                }
            } else {
                throw new UtilsException("ERROR: InputStream is NULL", ERROR_NULLINPUTSTREAM, CuaimaStream.CLASSID + "027");
            }

        } else {
            throw new UtilsException("ERROR: Decodification Parameters NOT Defined", ERROR_STREAMPARAMETERS, CuaimaStream.CLASSID + "028");
        }
    }

    /**
     * Retorna TRUE si se concluyo con el proceso de codificacion o FALSE si no.
     *
     * @return TRUE si se concluto o FASLE si no
     */
    @Override
    public boolean isDone() {
        boolean Result;

        this.rwl.readLock().lock();
        try {
            Result = this.isFinished;
        } finally {
            this.rwl.readLock().unlock();
        }
        return Result;
    }

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
    @Override
    public void Codec(InputStream Input, OutputStream Output, int Opciones) throws UtilsException {
        MersenneTwisterPlus Random;

        this.rwl.writeLock().lock();
        try {
            if ((this.Ejecutor == null) || (this.Ejecutor.getState() == Thread.State.TERMINATED)) {
                // Inicializa la Hebra del codificador
                Ejecutor = new Thread(this);
                Random = new MersenneTwisterPlus();
                Ejecutor.setName(this.CLASSID + "[" + Long.toHexString(Random.nextLong63()) + "]");
                Ejecutor.setUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
                    @Override
                    public void uncaughtException(Thread t, Throwable e) {
                        StringWriter StackTrace;
                        StringBuffer Message;
                        long StartTime, DiffTime;
                        LoggerFormatter BTLogF;

                        BTLogF = LoggerFormatter.getInstance(null);
                        BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "Uncaught Exception\n" + e.toString(), CuaimaStream.CLASSID, "029");
                        Message = new StringBuffer();
                        for (StackTraceElement STE : t.getStackTrace()) {
                            Message.append(STE.toString());
                        }
                        BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "Stack:\n" + Message.toString(), CuaimaStream.CLASSID, "030");
                        StackTrace = new StringWriter();
                        e.printStackTrace(new PrintWriter(StackTrace));
                        BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "StackTrace: " + StackTrace.toString(), CuaimaStream.CLASSID, "031");
                        DiffTime = 0;
                        StartTime = System.currentTimeMillis();
                        while ((t != null) && (t.getState() != Thread.State.TERMINATED) && (DiffTime < TIMEOUT)) {
                            try {
                                EnvironmentUtils.randomSleep(500);
                            } catch (UtilsException ex) {
                                BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, ex, null, CuaimaStream.CLASSID, "032");
                            } finally {
                                DiffTime = System.currentTimeMillis() - StartTime;
                            }
                        }
                        if (DiffTime >= TIMEOUT) {
                            BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_WARNING, false, null, "Thread Finished by TimeOut", CuaimaStream.CLASSID, "033");
                        }
                        if (Ejecutor != null) {
                            if (Ejecutor.getState() != Thread.State.TERMINATED) {
                                Ejecutor.interrupt();
                                BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_WARNING, false, null, "Forced Thread Finish by Interruption", CuaimaStream.CLASSID, "034");
                            }
                            Ejecutor = null;
                        }
                        rwl.writeLock().lock();
                        try {
                            isFinished = true;
                        } finally {
                            rwl.writeLock().unlock();
                        }
                    }
                });
                this.StreamParameters = new StreamOperationParameters(Input, Output, Opciones);
                this.Coding = true;
                this.ErrorCode = 0;
                this.isFinished = false;
                this.Continue = true;
                Ejecutor.start();
            } else {
                this.BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "Can't start Thread because the previous still is Running", CuaimaStream.CLASSID, "035");
            }
        } finally {
            this.rwl.writeLock().unlock();
        }
    }

    /**
     * Realiza la decodificacion de una cadena de bytes que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo.
     *
     * Si no logra decodificarlo retorna una cadena null.
     *
     * Ejemplo de Como Manejar la excepcion de que el Hash No Concuerda try {
     * Salida=CryptoBinary.Decodec(Entrada); } catch (UtilsException e) {
     * if(e.getErrorCode()==CuaimaBinary.HASHNOMACH){ System.out.println("HASH
     * NO CONCUERDA!!!"); } }
     *
     * @param Input Stream de Entrada codificada
     * @param Output Stream de Salida decodificar
     * @throws UtilsException Exceciones de decodificacion
     */
    @Override
    public void Decodec(InputStream Input, OutputStream Output) throws UtilsException {
        MersenneTwisterPlus Random;

        this.rwl.writeLock().lock();
        try {
            if ((this.Ejecutor == null) || (this.Ejecutor.getState() == Thread.State.TERMINATED)) {
                // Inicializa la Hebra del codificador
                Ejecutor = new Thread(this);
                Random = new MersenneTwisterPlus();
                Ejecutor.setName("CuaimaStream[" + Long.toHexString(Random.nextLong63()) + "]");
                Ejecutor.setUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
                    @Override
                    public void uncaughtException(Thread t, Throwable e) {
                        StringWriter StackTrace;
                        StringBuffer Message;
                        long StartTime, DiffTime;
                        LoggerFormatter BTLogF;

                        BTLogF = LoggerFormatter.getInstance(null);
                        BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "Uncaught Exception\n" + e.toString(), CuaimaStream.CLASSID, "036");
                        Message = new StringBuffer();
                        for (StackTraceElement STE : t.getStackTrace()) {
                            Message.append(STE.toString());
                        }
                        BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "Stack:\n" + Message.toString(), CuaimaStream.CLASSID, "037");
                        StackTrace = new StringWriter();
                        e.printStackTrace(new PrintWriter(StackTrace));
                        BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "StackTrace: " + StackTrace.toString(), CuaimaStream.CLASSID, "038");
                        DiffTime = 0;
                        StartTime = System.currentTimeMillis();
                        while ((t != null) && (t.getState() != Thread.State.TERMINATED) && (DiffTime < TIMEOUT)) {
                            try {
                                EnvironmentUtils.randomSleep(500);
                            } catch (UtilsException ex) {
                                BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, ex, null, CuaimaStream.CLASSID, "039");
                            } finally {
                                DiffTime = System.currentTimeMillis() - StartTime;
                            }
                        }
                        if (DiffTime >= TIMEOUT) {
                            BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_WARNING, false, null, "Thread Finished by TimeOut", CuaimaStream.CLASSID, "040");
                        }
                        if (Ejecutor != null) {
                            if (Ejecutor.getState() != Thread.State.TERMINATED) {
                                Ejecutor.interrupt();
                                BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_WARNING, false, null, "Forced Thread Finish by Interruption", CuaimaStream.CLASSID, "041");
                            }
                            Ejecutor = null;
                        }
                        rwl.writeLock().lock();
                        try {
                            isFinished = true;
                        } finally {
                            rwl.writeLock().unlock();
                        }
                    }
                });
                this.StreamParameters = new StreamOperationParameters(Input, Output, 0);
                this.Coding = false;
                this.ErrorCode = 0;
                this.isFinished = false;
                this.Continue = true;
                Ejecutor.start();
            } else {
                BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, null, "Can't start Thread because the previous still is Running", CuaimaStream.CLASSID, "042");
            }
        } finally {
            this.rwl.writeLock().unlock();
        }
    }

    /**
     * Recupera el codigo de Error de la Ejecucion del algoritmo
     *
     * @return Codigo de Error de la Ejecucion del Algoritmo
     */
    public int getErrorCode() {
        int Result;

        this.rwl.readLock().lock();
        try {
            Result = ErrorCode;
        } finally {
            this.rwl.readLock().unlock();
        }
        return Result;
    }

    /**
     * Retorna TRUE si se produjo un error en la ejecucion del algoritmo de
     * codificacion o FALSE si no.
     *
     * @return TRUE si Error o FALSE si no se produjo Error
     */
    public boolean hasError() {
        boolean Result = false;

        this.rwl.readLock().lock();
        try {
            if ((this.Ejecutor != null) || (this.Ejecutor.getState() == Thread.State.TERMINATED)) {
                if (this.ErrorCode != 0) {
                    Result = true;
                }
            }
        } finally {
            this.rwl.readLock().unlock();
        }
        return Result;
    }

    /**
     * Ejecuta la Hebra que procesa el archivo
     */
    @Override
    public void run() {

        try {
            if (this.Coding) {
                this.PrivCodec();
            } else {
                this.PrivDecodec();
            }
        } catch (UtilsException ex) {
            try {
                if (this.StreamParameters.Input != null) {
                    this.StreamParameters.Input.close();
                }
                if (this.StreamParameters.Output != null) {
                    this.StreamParameters.Output.flush();
                    this.StreamParameters.Output.close();
                }
            } catch (IOException exx) {
                this.BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, exx, null, CuaimaStream.CLASSID, "043");
            }
            this.rwl.writeLock().lock();
            try {
                this.ErrorCode = ex.getErrorCode();
            } finally {
                this.rwl.writeLock().unlock();
            }
            this.BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, ex, null, CuaimaStream.CLASSID, "044");
        } finally {
            this.rwl.writeLock().lock();
            try {
                this.isFinished = true;
                this.Ejecutor = null;
            } finally {
                this.rwl.writeLock().unlock();
            }
        }
    }

    /**
     * Clase privada que almacena la informacion de los archivos a procesar asi
     * como las opciones a utilizar
     *
     */
    private class StreamOperationParameters {

        // Los lock para el manejo de concurrencia
        private final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();

        private InputStream Input;
        private OutputStream Output;
        private int Opciones;

        /**
         * Constructor por defecto
         *
         * @param Input Stream de Entrada
         * @param Output Stream de Salida
         * @param Opciones Parametros de configuracion del codificador
         */
        public StreamOperationParameters(InputStream Input, OutputStream Output, int Opciones) {
            this.Input = Input;
            this.Output = Output;
            this.Opciones = Opciones;
        }

        /**
         * Retorna el Input Stream
         *
         * @return Input Stream
         */
        public InputStream getInput() {
            InputStream Result;

            this.rwl.readLock().lock();
            try {
                Result = this.Input;
            } finally {
                this.rwl.readLock().unlock();
            }
            return Result;
        }

        /**
         * Establece el Input Stream
         *
         * @param Input Input Stream
         */
        public void setInput(InputStream Input) {

            this.rwl.writeLock().lock();
            try {
                this.Input = Input;
            } finally {
                this.rwl.writeLock().unlock();
            }
        }

        /**
         * Retorna el Output Stream
         *
         * @return Output Stream
         */
        public OutputStream getOutput() {
            OutputStream Result;

            this.rwl.readLock().lock();
            try {
                Result = this.Output;
            } finally {
                this.rwl.readLock().unlock();
            }
            return Result;
        }

        /**
         * Establece el Output Stream
         *
         * @param Output Output Stream
         */
        public void setOutput(OutputStream Output) {

            this.rwl.writeLock().lock();
            try {
                this.Output = Output;
            } finally {
                this.rwl.writeLock().unlock();
            }
        }

        /**
         * Retorna las opciones para la codificacion del archivo.
         *
         * @return Opciones para la codificacion del archivo.
         */
        public int getOpciones() {
            int Result;

            this.rwl.readLock().lock();
            try {
                Result = this.Opciones;
            } finally {
                this.rwl.readLock().unlock();
            }
            return Result;
        }

        /**
         * Establece las opciones para la codificacion del archivo.
         *
         * @param Opciones Opciones para la codificacion del archivo.
         */
        public void setOpciones(int Opciones) {

            this.rwl.writeLock().lock();
            try {
                this.Opciones = Opciones;
            } finally {
                this.rwl.writeLock().unlock();
            }
        }
    }
}
