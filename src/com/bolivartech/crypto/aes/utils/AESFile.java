package com.bolivartech.crypto.aes.utils;

import com.bolivartech.crypto.aes.CuaimaAES;
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
import com.bolivartech.crypto.interfaces.CryptoFile;
import com.bolivartech.utils.array.ArrayUtils;
import com.bolivartech.utils.converters.Converter;
import com.bolivartech.utils.exception.UtilsException;
import com.bolivartech.utils.files.*;
import com.bolivartech.utils.log.LoggerManager;
import com.bolivartech.utils.math.MathUtil;
import com.bolivartech.utils.random.MersenneTwisterPlus;
import com.bolivartech.utils.btthreads.annotations.GuardedBy;
import com.bolivartech.utils.btthreads.annotations.ThreadSafe;
import com.bolivartech.utils.log.LoggerFormatter;
import java.io.File;
import java.util.Arrays;

/**
 * <p>
 * Copyright 2007,2009,2010 BolivarTech INC</p>
 *
 * <p>
 * Homepage: <a
 * href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.</p>
 * <p>
 * BolivarTech Homepage: <a
 * href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 * <p>
 * This Class is the CuaimaCrypt's util for code files.</p>
 *
 * <p>
 * Realiza la encryptacion y desencryptacion de un archivo basado en un password
 * de 1 caracter minimos, retornando un archivo encriptado.</p>
 *
 * <ul>
 * <li>Class ID: "TR74ID6"</li>
 * <li>Loc: 000-038</li>
 * </ul>
 *
 * @author Julian Bolivar
 * @since 2007 | 2016-03-25
 * @version 3.1.2
 *
 * <p>
 * Change Log:
 * </p>
 * <ul>
 * <li>v3.1.2 (2016-03-25) Se agrego el codigo de localizacion para la excepcion
 * y bitacoras.</li>
 * <li>v3.1.1 - Se solventa bug al recuperar el valor del tamaño de
 * entrada.</li>
 * <li>v3.1.0 - Se implementa la codificacion y decodificacion asincrona del
 * archivo.</li>
 * <li>v3.0.0 - Se realiza la estandarizacion de la mascara para el control de
 * Versiones.</li>
 * <li>v2.1.0 - Se Agrego Soporte de Hash para verificar que el archivo fue
 * codificado correctarmente.</li>
 * <li>v2.0.0 - The Random generator is initializated using the new class
 * MersenneTwisterPlus that was implemente by BolivarTech.</li>
 * </ul>
 */
@ThreadSafe
public class AESFile implements CryptoFile, Runnable {

    // Codigo de identificacion de la clase
    private static final String CLASSID = "TR74ID6";

    // Manejador de Bitacoras
    private LoggerFormatter BTLogF;
    @GuardedBy("AES")
    private CuaimaAES AES;
    private int PasswdLength;
    private double HeadPos;
    @GuardedBy("this")
    private int BufferSize; // Tamaño del buffer de lectura en 
    @GuardedBy("this")
    private int Progress;
    @GuardedBy("FileParameters")
    private FileOperationParameters FileParameters;
    // Hebra de ejecucion de la codificacion o Decodificacion
    private Thread Ejecutando = null;
    // TRUE si es para codificar y FALSE si es para Decodificar
    private boolean Coding = true;
    @GuardedBy("this")
    int ErrorCode = 0;  // Codigo de Error de la Ejecicion

    /**
     * Version del algoritmo CuaimaCryptFile (NOTA: Maximo hasta 255 porque son
     * solo 8 bits)
     */
    private final static short VERSION = 3;

    /**
     * Mascara para recuperar el valor del algoritmo de HASH
     */
    private final static int HASHMASK = 31;

    /**
     * Calcula la posicion del encabezado, retornando un porcentaje que sera
     * utilizado para determinar la posicion en el mensaje
     *
     * @param Password
     */
    private strictfp void CalcHeadPos(String Password) {
        long Temp;
        int i;

        // Calcula la posicion del encabezado en un porcentaje
        Temp = 0;
        for (i = 0; i < Password.length(); i++) {
            Temp += (long) Password.charAt(i);
        }
        HeadPos = (double) Temp;
        HeadPos /= 100;
        Temp = (long) HeadPos;
        HeadPos -= Temp;
        try {
            HeadPos = MathUtil.roundToDecimals(HeadPos, 2);
        } catch (UtilsException ex) {
            synchronized (this) {
                this.ErrorCode = ERROR_HEADPOSSITIONERROR;
            }
            this.BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, ex, null, AESFile.CLASSID, "000");
        }
        if (HeadPos > 0.8) {
            HeadPos = 0.8;
        }
    }

    /**
     * Constructor por defecto de AESFile, utilizando 9 bloques de RakeCodecs.
     *
     * @param Log Manejador de bitacoras
     */
    public AESFile(LoggerManager Log) {

        Progress = 0;
        PasswdLength = -1;
        synchronized (this) {
            BufferSize = 52428800;  // 50 MB
            AES = new CuaimaAES();
        }
        this.BTLogF = LoggerFormatter.getInstance(Log); // Manejador de Logs
    }

    /**
     * Constructor con inicializacion del password de AESFile, utilizando 9
     * bloques de RakeCodecs
     *
     * @param Password password de codificacion
     * @param Log Manejador de bitacora
     * @throws UtilsException Excepcion de inicializacion
     */
    public AESFile(String Password, LoggerManager Log) throws UtilsException {

        Progress = 0;
        this.BTLogF = LoggerFormatter.getInstance(Log); // Manejador de Logs
        synchronized (this) {
            BufferSize = 52428800;  // 50 MB
            AES = new CuaimaAES();
        }
        synchronized (AES) {
            if (AES.Password(Password) != 0) {
                PasswdLength = -1;
                synchronized (this) {
                    this.Progress = -1;
                }
                throw new UtilsException("ERROR: NO se pudo inicializar AESFile, falla al inicializar el Password", ERROR_PASSWD, AESFile.CLASSID + "001");
            } else {
                PasswdLength = Password.length();
                this.CalcHeadPos(Password);
            }
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
     * Establece la clave que utiliza AESFile para codificar el texto, la cual
     * debe de tener como minimo un caracter de longitud
     *
     * @param Passw Clave a utilizar
     * @return true si lo logro y false si no
     * @throws UtilsException Excepcion de establecimiento de clave
     */
    @Override
    public boolean Password(String Passw) throws UtilsException {
        boolean salida;

        salida = false;
        PasswdLength = -1;
        if (AES != null) {
            synchronized (AES) {
                if (AES.Password(Passw) != 0) {
                    synchronized (this) {
                        this.Progress = -1;
                    }
                    throw new UtilsException("ERROR: NO se pudo inicializar la clave en AESFile", ERROR_PASSWD, AESFile.CLASSID + "002");
                } else {
                    PasswdLength = Passw.length();
                    this.CalcHeadPos(Passw);
                    salida = true;
                }
            }
        }
        return salida;
    }

    /**
     * Retorna el numero de bytes del buffer de lectura para la codificacion del
     * archivo.
     *
     * @return Tamaño del buffer en bytes
     */
    @Override
    public synchronized int getBufferSize() {
        return BufferSize;
    }

    /**
     * Establece el numero de bytes para el buffer de lectura para la carga del
     * archivo a codificar.
     *
     * El buffer minimo sera de 16 bytes que es equivalente a 128 bits
     *
     * @param BufferSize (bytes)
     */
    @Override
    public synchronized void setBufferSize(int BufferSize) {
        if (BufferSize < 16) {
            this.BufferSize = 16;
        } else {
            this.BufferSize = (int) (16 * Math.ceil((double) BufferSize / 16));  // verifica que sea multiplo de 16
        }
    }

    /**
     * Realiza la codificacion de un archivo, del que recibe en Input el objeto
     * que lo define, en base a la clave con la cual se inicializo el algoritmo;
     * generando el archivo codificado especificado en Output; si Output es
     * 'null' utiliza el mismo nombre del archivo de entrada y le agrega la
     * extencion .caes
     *
     * Si Output existe es borrado de forma NO SEGURA porque se presupone que si
     * existe es un archivo ya codificado.
     *
     * En opciones se especifican los parametros de configuracion del algoritmo
     * concatenados con 'or' |
     *
     * Ejemplo de Como Manejar la excepcion de no poder abrir el archivo de
     * entrada try { Salida=AESFile.Codec(Entrada,null,CuimaFile.SHA1); } catch
     * (UtilsException e) { if(e.getErrorCode()==AESFile.NOOPENINFILE){
     * System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!"); } }
     *
     * @throws UtilsException
     */
    private void PrivCodec() throws UtilsException {
        MersenneTwisterPlus Rand;
        int i, j;
        long NumBytesReads;
        long DTemp;
        byte InputBuffer[];
        byte SubInputBuffer[];
        long InputFileLength;
        long OutputCodecFileLength;
        long k;
        long Header[];
        long CBuffer[];
        long HPosc;
        long NumBlockWrite;
        String InputFileName;
        StringBuffer TempInputFileName;
        String InputFilePath;
        String Separador;
        String OutputFileName;
        int HashType;
        BaseHash Hash;
        boolean HeaderAdded;
        byte[] Temp;
        FileManager Input;
        FileManager Output;
        int Opciones;

        // Verifica si el algoritmo fue inicializado
        if (FileParameters != null) {
            Input = FileParameters.getInput();
            Output = FileParameters.getOutput();
            Opciones = FileParameters.getOpciones();
            if (Input.getFileLength() > 0) {
                if (PasswdLength > 0) {
                    if (Input.isFile()) {
                        // Inicializa el generador de numeros aleatorios
                        Rand = new MersenneTwisterPlus();
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
                        // Se recupera los parametros del archivo original
                        InputFileLength = Input.getFileLength();
                        if (InputFileLength < 0) {
                            InputFileLength = 0;
                        }
                        InputFileName = Input.getFileName();
                        InputFilePath = Input.getFilePath(); //  getPath(); // getAbsolutePath();
                        Separador = Input.getSeparador();
                        // Genera el Encabezado del archivo
                        k = (long) (8 * Math.ceil((double) InputFileName.length() / 8)); //determina el proximo numero multiplo de bloques de 64 bits que puede almacenar el nombre del archivo
                        k = k / 8;  //determina cuantos bloques de 64 bits se necesitan para almacenar el nombre del archivo
                        k = (long) (2 * Math.ceil((double) k / 2)); // Se Asegura que la cantidad de bloques del nombre sea multiplo de 2
                        TempInputFileName = new StringBuffer(InputFileName);
                        for (i = InputFileName.length(); i < k * 8; i++) {
                            TempInputFileName.append((char) (97 + 25 * Rand.nextReal()));
                        }
                        Header = new long[8 + (int) (k)];
                        Header[0] = (Rand.nextLong() << 32) | (Converter.byte2long(new String("CAESSEAC").getBytes())[0] >>> 32);  // BYTES de OFUSCACION
                        Header[1] = (Converter.byte2long(new String("CAESSEAC").getBytes())[0] << 32) | (Rand.nextLong() >>> 32);  // BYTES de OFUSCACION
                        Header[2] = ((long) InputFileName.length()) | ((long) Header.length << 32);  // Longitud del Encabezado y del Nombre del Archivo almacenado en dos enteros de 32 bits
                        Header[3] = InputFileLength;
                        for (i = 0; i < k; i++) {
                            Header[4 + i] = Converter.byte2long(TempInputFileName.substring(i * 8, (i + 1) * 8).getBytes())[0];
                        }
                        Header[(int) (Header.length - 4)] = Rand.nextLong();        // BYTES de OFUSCACION
                        Header[(int) (Header.length - 3)] = Rand.nextLong() << 32;  // BYTES de OFUSCACION
                        Header[(int) (Header.length - 3)] |= HashType << 26;        // Hash usado en el archivo
                        Header[(int) (Header.length - 3)] |= VERSION & 0xFF;                    // VERSION DE CUAIMAFILE
                        Header[(int) (Header.length - 2)] = (Rand.nextLong() << 32) | (Converter.byte2long(new String("CAESSEAC").getBytes())[0] >>> 32);  // BYTES de OFUSCACION
                        Header[(int) (Header.length - 1)] = (Converter.byte2long(new String("CAESSEAC").getBytes())[0] << 32) | (Rand.nextLong() >>> 32);  // BYTES de OFUSCACION
                        // Verifica si el archivo de Salida es lo suficientemente grande para contener el encabezado
                        // Para esto se verifica si la longitud del 10% del archivo de entrada es mayor a la
                        // longitud del encabezado, en caso contrario semajusta para un valor minimo del 7%
                        // que lo pueda contener
                        OutputCodecFileLength = (long) Math.ceil((double) InputFileLength * 0.1);
                        if (Header.length > OutputCodecFileLength) {
                            InputFileLength = 56 * Header.length;
                        }
                        // Calcula el tamaño del archivo de salida en bloques de 64 bits
                        if (Hash != null) {
                            OutputCodecFileLength = (long) Hash.hashSize();
                            OutputCodecFileLength = (long) Math.ceil((double) (InputFileLength + OutputCodecFileLength) / 8);
                            OutputCodecFileLength = (long) ((long) 16 * Math.ceil((double) (Header.length + OutputCodecFileLength) / 16));
                            //OutputCodecFileLength = (long) (16 * Math.ceil(Math.ceil(((long) Header.length + Math.ceil((InputFileLength + (long) Hash.hashSize()) / 8))) / 16));
                        } else {
                            OutputCodecFileLength = (long) Math.ceil((double) InputFileLength / 8);
                            OutputCodecFileLength = (long) ((long) 16 * Math.ceil((double) (Header.length + OutputCodecFileLength) / 16));
                            //OutputCodecFileLength = (long) (16 * Math.ceil(Math.ceil(((long) Header.length + Math.ceil(InputFileLength / 8))) / 16));
                        }
                        // Calcula la posicion del Header en el archivo
                        HPosc = (long) (HeadPos * OutputCodecFileLength);
                        HPosc = (long) (2 * Math.ceil((double) HPosc / 2));
                        // Define el archivo de salida si no fue especificado
                        if (Output == null) {
                            OutputFileName = new String(InputFilePath + Separador + Input.getFileBaseName() + ".caes");
                            Output = new FileManager(OutputFileName);
                        } else if ((Output != null) && (Output.isDirectory())) {
                            OutputFileName = new String(Input.getFileBaseName() + ".caes");
                            Output = new FileManager(Output.getFilePath() + Output.getSeparador() + OutputFileName);
                        }
                        // Almacena el file manager del archivo de Salida
                        FileParameters.setOutput(Output);
                        // Realiza la creacion del archivo de salida;
                        if (Output.Exists()) {
                            if (!Output.Delete()) {
                                // Error al eliminar archivo de salida existente
                                synchronized (this) {
                                    this.Progress = -1;
                                }
                                throw new UtilsException("ERROR: NO se pudo borrar el archivo de salida existente", ERROR_DELETEOUTFILE, AESFile.CLASSID + "003");
                            }
                        }
                        try {
                            Output.Open(FileManager.WRITE, false);
                        } catch (UtilsException ex) {
                            // error al crear el archivo de salida
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se pudo crear el archivo " + Output.getAbsoluteFilePath(), ERROR_CREATEOUTFILE, AESFile.CLASSID + "004");
                        }
                        try {
                            Input.Open(FileManager.READ, false);
                        } catch (UtilsException ex) {
                            // Error al abrir el archivo de entrada
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se pudo abrir el archivo " + Input.getAbsoluteFilePath(), ERROR_OPENINFILE, AESFile.CLASSID + "005");
                        }
                        // Codifica el Encabezado del archivo
                        CBuffer = new long[2];
                        for (i = 0; i < Header.length; i += 2) {
                            CBuffer[0] = Header[i];
                            CBuffer[1] = Header[i + 1];
                            Temp = Converter.long2byte(CBuffer);
                            synchronized (AES) {
                                Temp = AES.Encrypt(Temp);
                            }
                            CBuffer = Converter.byte2long(Temp);
                            Header[i] = CBuffer[0];
                            Header[i + 1] = CBuffer[1];
                        }
                        // Codifica el archivo de entrada
                        synchronized (this) {
                            InputBuffer = new byte[this.BufferSize]; // Buffer de Entrada
                        }
                        SubInputBuffer = new byte[16];
                        NumBytesReads = InputBuffer.length;
                        NumBlockWrite = 0;
                        HeaderAdded = false;
                        // Lectura del archivo de entrada
                        while (InputBuffer.length == NumBytesReads) {
                            try {
                                NumBytesReads = Input.Read(InputBuffer);
                            } catch (UtilsException ex) {
                                // Error de lectura del archivo de entrada
                                synchronized (this) {
                                    this.Progress = -1;
                                }
                                throw new UtilsException("ERROR: NO se puedo leer el archivo a codificar", ERROR_NOREADINFILE, AESFile.CLASSID + "006");
                            }
                            // Verifica si se leyeron datos
                            if (NumBytesReads > 0) {
                                // Actualiza el Hash
                                if (Hash != null) {
                                    Hash.update(InputBuffer, 0, (int) NumBytesReads);
                                }
                                // Verifica si se llego al final del archivo
                                if (NumBytesReads < InputBuffer.length) {
                                    DTemp = NumBytesReads;
                                    // Redimenciona el buffer para contener el Hash
                                    // verificando que el numero de bytes sea multiplo de 16
                                    if (Hash != null) {
                                        NumBytesReads = (int) (16 * Math.ceil((double) (NumBytesReads + Hash.hashSize()) / 16));
                                    } else {
                                        NumBytesReads = (int) (16 * Math.ceil((double) (NumBytesReads) / 16));
                                    }
                                    if ((NumBlockWrite + (NumBytesReads / 8)) != OutputCodecFileLength) {
                                        if (HeaderAdded) {
                                            NumBytesReads = (int) (8 * (OutputCodecFileLength - NumBlockWrite));
                                        } else {
                                            NumBytesReads = (int) (8 * (OutputCodecFileLength - NumBlockWrite - Header.length));
                                        }
                                    }
                                    InputBuffer = (byte[]) ArrayUtils.resizeArray(InputBuffer, (int) NumBytesReads);
                                    // Agrega el Hash del archivo original al buffer 
                                    if (Hash != null) {
                                        ArrayUtils.arrayCopy(Hash.digest(), 0, InputBuffer, (int) DTemp, Hash.hashSize());
                                        // Completa los datos agregados con numeros aleatorios
                                        for (i = (int) (DTemp + Hash.hashSize()); i < NumBytesReads; i++) {
                                            InputBuffer[i] = Rand.nextByte();
                                        }
                                    } else {
                                        // Completa los datos agregados con numeros aleatorios
                                        for (i = (int) DTemp; i < NumBytesReads; i++) {
                                            InputBuffer[i] = Rand.nextByte();
                                        }
                                    }
                                }
                                // Realiza la codificacion del buffer leido desde el archivo
                                for (i = 0; i < NumBytesReads; i += 16) {
                                    for (j = 0; j < 16; j++) {
                                        SubInputBuffer[j] = InputBuffer[i + j];
                                    }
                                    // Codifica el bloque de 128 bits
                                    synchronized (AES) {
                                        SubInputBuffer = AES.Encrypt(SubInputBuffer);
                                    }
                                    for (j = 0; j < 16; j++) {
                                        InputBuffer[i + j] = SubInputBuffer[j];
                                    }
                                }
                                // Escribe en el archivo de salida, agregando el encabezado en el lugar calculado
                                if ((NumBlockWrite <= HPosc) && (NumBlockWrite + (NumBytesReads / 8) >= HPosc)) {
                                    // Estamos en el bloque donde se inserta el encabezado
                                    DTemp = (int) (8 * (HPosc - NumBlockWrite)); //Numero de bloques antes del encabezado
                                    try {
                                        // Escribe los bloques antes del encabezado
                                        Output.Write(InputBuffer, 0, (int) DTemp);
                                        // Escribe el encabezado
                                        Output.Write(Converter.long2byte(Header), 0, 8 * Header.length);
                                        // Escribe el resto del bloque despues del encabezado
                                        Output.Write(InputBuffer, (int) DTemp, (int) (NumBytesReads - DTemp));
                                    } catch (UtilsException ex) {
                                        // Error de escritura del archivo de salida
                                        synchronized (this) {
                                            this.Progress = -1;
                                        }
                                        throw new UtilsException("ERROR: NO se puede escribir en el archivo " + Output.getAbsoluteFilePath(), ERROR_WRITEOUTFILE, AESFile.CLASSID + "007");
                                    }
                                    NumBlockWrite += (NumBytesReads / 8) + Header.length;
                                    HeaderAdded = true;
                                } else {
                                    try {
                                        // Escribe el bloque de datos
                                        Output.Write(InputBuffer, 0, (int) NumBytesReads);
                                    } catch (UtilsException ex) {
                                        // Error de escritura del archivo de salida
                                        synchronized (this) {
                                            this.Progress = -1;
                                        }
                                        throw new UtilsException("ERROR: NO se puede escribir en el archivo " + Output.getAbsoluteFilePath(), ERROR_WRITEOUTFILE, AESFile.CLASSID + "008");
                                    }
                                    NumBlockWrite += NumBytesReads / 8;
                                }
                            }
                            // Calcula el Porcentaje de Avance en al codificacion del Archivo
                            DTemp = (NumBlockWrite * 100) / OutputCodecFileLength;
                            if (DTemp == 100) {
                                DTemp = 99;
                            }
                            synchronized (this) {
                                this.Progress = (int) DTemp;
                            }
                        }
                        try {
                            Input.Close();
                        } catch (UtilsException ex) {
                            // Error al cerrar el archivo de entrada
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se puede cerrar el archivo " + Input.getAbsoluteFilePath(), ERROR_CLOSEINFILE, AESFile.CLASSID + "009");
                        }
                        try {
                            Output.Close();
                        } catch (UtilsException ex) {
                            // Error al cerrar el archivo de salida
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se puede cerrar el archivo " + Output.getAbsoluteFilePath(), ERROR_CLOSEOUTFILE, AESFile.CLASSID + "010");
                        }
                    } else {
                        synchronized (this) {
                            this.Progress = -1;
                        }
                        throw new UtilsException("ERROR: NO se puede identificar el tipo de archivo a codificar", ERROR_INFILETYPE, AESFile.CLASSID + "011");
                    }
                } else {
                    synchronized (this) {
                        this.Progress = -1;
                    }
                    throw new UtilsException("ERROR: Clave NO definida para codificar archivo", ERROR_PASSWD, AESFile.CLASSID + "012");
                }
            } else {
                synchronized (this) {
                    this.Progress = -1;
                }
                throw new UtilsException("ERROR: Achivo de entrada tiene tamaño 0", ERROR_INPUTFILEZEROSIZE, AESFile.CLASSID + "013");
            }
        } else {
            synchronized (this) {
                this.Progress = -1;
            }
            throw new UtilsException("ERROR: Archivos y Parametros de Codificacion NO Definidos", ERROR_FILEPARAMETERS, AESFile.CLASSID + "014");
        }
        synchronized (this) {
            this.Progress = 100;
        }
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
     * entrada try { Salida=AESFile.Codec(Entrada,null,CuimaFile.SHA1); } catch
     * (UtilsException e) { if(e.getErrorCode()==AESFile.NOOPENINFILE){
     * System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!"); } }
     *
     * @throws UtilsException
     */
    private void PrivDecodec() throws UtilsException {
        int i, j;
        int Resultado = 0;
        long NumBytesReads;
        int HeaderLength;
        int DTemp;
        int OutputFileNameLength;
        long HPosc;
        long Header[], HTemp[];
        long DcBuffer[];
        long NumBytesWrite;
        long NumBlocksRead;
        String InputCodecFileName;
        String InputCodecFilePath;
        String Separador;
        String OutputFileName;
        String HeaderDec;
        long InputCodecFileLength;
        long OutputFileLength;
        byte InputBuffer[];
        byte SubInputBuffer[];
        int HashType;
        BaseHash Hash;
        byte[] OrgDigest = null;
        byte[] NewDigest = null;
        int Version;
        byte[] Temp;
        FileManager Input;
        FileManager Output;

        // Verifica si el algoritmo fue inicializado
        if (FileParameters != null) {
            Input = FileParameters.getInput();
            Output = FileParameters.getOutput();
            if (Input.getFileLength() > 0) {
                if (PasswdLength > 0) {
                    if (Input.isFile()) {
                        // Se recupera los parametros del archivo codificado
                        // Tamaño del archivo de codificado en bloques de 64 bits
                        InputCodecFileLength = (long) Math.ceil((double) Input.getFileLength() / 8);
                        InputCodecFileName = Input.getFileName();
                        InputCodecFilePath = Input.getFilePath();
                        Separador = File.separator;
                        // Calcula la posicion del Header en el archivo
                        HPosc = (long) (HeadPos * InputCodecFileLength);
                        HPosc = (long) (2 * Math.ceil((double) HPosc / 2));
                        try {
                            // Abre el archivo de entrada
                            Input.Open(FileManager.READ, false);
                        } catch (UtilsException ex) {
                            // Error al abrir el archivo de entrada
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se pudo abrir el archivo " + Input.getAbsoluteFilePath(), ERROR_OPENINFILE, AESFile.CLASSID + "015");
                        }
                        // Trata de recuperar el encabezado
                        InputBuffer = new byte[32]; // Buffer de Entrada

                        try {
                            Input.Skip(8 * HPosc);
                            NumBytesReads = Input.Read(InputBuffer);
                        } catch (UtilsException ex) {
                            // No se pudo leer el archivo de entrada
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "016");
                        }
                        if (NumBytesReads == 32) {
                            Header = Converter.byte2long(InputBuffer);
                        } else {
                            // No se pudo leer el archivo de entrada
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "017");
                        }
                        // Decodifica el Encabezado del archivo
                        DcBuffer = new long[2];
                        for (i = 0; i < Header.length; i += 2) {
                            DcBuffer[0] = Header[i];
                            DcBuffer[1] = Header[i + 1];
                            Temp = Converter.long2byte(DcBuffer);
                            synchronized (AES) {
                                Temp = AES.Decrypt(Temp);
                            }
                            DcBuffer = Converter.byte2long(Temp);
                            Header[i] = DcBuffer[0];
                            Header[i + 1] = DcBuffer[1];
                        }
                        // Trata de Recuperar Informacion del Encabezado
                        HTemp = new long[1];
                        HTemp[0] = (Header[0] << 32) | (Header[1] >>> 32);
                        HeaderDec = new String(Converter.long2byte(HTemp));
                        // Verifica si se pudo recuperar la informacion del encabezado
                        if (HeaderDec.contentEquals(new StringBuffer("CAESSEAC"))) {
                            // Tamaño del archivo de salida en Bytes
                            OutputFileLength = Header[3];
                            if (OutputFileLength < 0) {
                                OutputFileLength = 0;
                            }
                            // Recupera el tamaño del nombre del archivo de salida
                            //OutputFileNameLength = (int) ((Header[2] << 32) >>> 32);
                            OutputFileNameLength = (int) (Header[2] & 0xFFFFFFFF);
                            // Recupera el tamaño del encabezado
                            HeaderLength = (int) (Header[2] >>> 32);
                            // Cambia el tamaño del encabezado para contenerlo completo
                            Header = (long[]) ArrayUtils.resizeArray(Header, HeaderLength);
                            // Trata de recuperar el resto del encabezado encabezado
                            InputBuffer = new byte[8 * (HeaderLength - 4)]; // Buffer de Entrada
                            try {
                                NumBytesReads = Input.Read(InputBuffer);
                            } catch (UtilsException ex) {
                                // No se pudo leer el archivo de entrada
                                synchronized (this) {
                                    this.Progress = -1;
                                }
                                throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "018");
                            }
                            if (NumBytesReads == (8 * (HeaderLength - 4))) {
                                HTemp = Converter.byte2long(InputBuffer);
                            } else {
                                // No se pudo leer el archivo de entrada
                                synchronized (this) {
                                    this.Progress = -1;
                                }
                                throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "019");
                            }
                            //Decodifica el Encabezado recuperado
                            DcBuffer = new long[2];
                            for (i = 0; i < HTemp.length; i += 2) {
                                DcBuffer[0] = HTemp[i];
                                DcBuffer[1] = HTemp[i + 1];
                                Temp = Converter.long2byte(DcBuffer);
                                synchronized (AES) {
                                    Temp = AES.Decrypt(Temp);
                                }
                                DcBuffer = Converter.byte2long(Temp);
                                HTemp[i] = DcBuffer[0];
                                HTemp[i + 1] = DcBuffer[1];
                            }
                            // Reconstruye el Encabezado
                            for (i = 0; i < HTemp.length; i++) {
                                Header[4 + i] = HTemp[i];
                            }
                            // Verifica si se pudo recuperar el encabezado completo
                            HTemp = new long[1];
                            HTemp[0] = (Header[HeaderLength - 2] << 32) | (Header[HeaderLength - 1] >>> 32);
                            HeaderDec = new String(Converter.long2byte(HTemp));
                            if (HeaderDec.contentEquals(new StringBuffer("CAESSEAC"))) {
                                // Verifica la Version
                                Version = (int) (Header[(int) (Header.length - 3)] & 0xFFL);
                                if (Version == (VERSION & 0xFF)) {
                                    // Recupera el Tipo de Hash utilizado
                                    HashType = ((int) (Header[(int) (Header.length - 3)] >>> 26)) & HASHMASK;
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
                                    // Especifica el archivo de salida
                                    if ((Output == null) || (Output.isDirectory())) {
                                        // Recupera el Nombre del archivo original
                                        HTemp = new long[HeaderLength - 8];
                                        for (i = 0; i < HTemp.length; i++) {
                                            HTemp[i] = Header[4 + i];
                                        }
                                        OutputFileName = new String(Converter.long2byte(HTemp));
                                        OutputFileName = OutputFileName.substring(0, OutputFileNameLength);
                                        if ((Output != null) && (Output.isDirectory())) {
                                            Output = new FileManager(Output.getFilePath() + Output.getSeparador() + OutputFileName);
                                        } else {
                                            Output = new FileManager(InputCodecFilePath + Input.getSeparador() + OutputFileName);
                                        }
                                        // Almacena el file manager del archivo de Salida
                                        FileParameters.setOutput(Output);
                                    }
                                    // Realiza la creacion del archivo de salida;
                                    if (Output.Exists()) {
                                        if (!Output.Delete()) {
                                            // Error al eliminar archivo de salida existente
                                            synchronized (this) {
                                                this.Progress = -1;
                                            }
                                            throw new UtilsException("ERROR: NO se pudo borrar el archivo " + Output.getAbsoluteFilePath(), ERROR_DELETEOUTFILE, AESFile.CLASSID + "020");
                                        }
                                    }
                                    // Abre el archivo de salida
                                    try {
                                        Output.Open(FileManager.WRITE, false);
                                    } catch (UtilsException ex) {
                                        // error al crear el archivo de salida
                                        synchronized (this) {
                                            this.Progress = -1;
                                        }
                                        throw new UtilsException("ERROR: NO se pudo crear el archivo " + Output.getAbsoluteFilePath(), ERROR_CREATEOUTFILE, AESFile.CLASSID + "021");
                                    }
                                    // Decodifica el resto del archivo
                                    try {
                                        Input.Reset();
                                    } catch (UtilsException ex) {
                                        // Error al abrir el archivo de entrada
                                        synchronized (this) {
                                            this.Progress = -1;
                                        }
                                        throw new UtilsException("ERROR: NO se pudo abrir el archivo " + Input.getAbsoluteFilePath(), ERROR_OPENINFILE, AESFile.CLASSID + "022");
                                    }
                                    synchronized (this) {
                                        InputBuffer = new byte[this.BufferSize]; // Buffer de Entrada
                                    }
                                    SubInputBuffer = new byte[16];
                                    NumBytesReads = InputBuffer.length;
                                    NumBytesWrite = 0;
                                    NumBlocksRead = 0;
                                    while (InputBuffer.length == NumBytesReads) {
                                        try {
                                            // Lectura del archivo de entrada
                                            NumBytesReads = Input.Read(InputBuffer);
                                        } catch (UtilsException ex) {
                                            // No se pudo leer el archivo de entrada
                                            synchronized (this) {
                                                this.Progress = -1;
                                            }
                                            throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "023");
                                        }
                                        // Verifica si se leyeron datos
                                        if (NumBytesReads > 0) {
                                            // Elimina el encabezado del archivo de entrada
                                            if ((NumBlocksRead <= HPosc) && (NumBlocksRead + (NumBytesReads / 8) > HPosc)) {
                                                // Estamos en el bloque donde se encuentra el encabezado
                                                DTemp = (int) (8 * (HPosc - NumBlocksRead)); //Numero de bytes antes del encabezado en el buffer
                                                // Determina si el encabezado esta completo en el buffer
                                                if ((DTemp + (8 * HeaderLength)) < InputBuffer.length) {
                                                    // Elimina el encabezado si esta contenido en el buffer 
                                                    for (i = DTemp; i < (InputBuffer.length - (8 * HeaderLength)); i++) {
                                                        InputBuffer[i] = InputBuffer[i + (8 * HeaderLength)];
                                                    }
                                                    // De la cantidad de bytes leidos elimino el encabezado
                                                    NumBytesReads -= (8 * HeaderLength);
                                                    // Genera un subuffer para leer los datos eliminados
                                                    SubInputBuffer = new byte[8 * HeaderLength];
                                                } else {
                                                    // Determino la cantidad de bytes del encabezado que
                                                    // estan delante del fin del buffer 
                                                    i = (8 * HeaderLength) + DTemp - InputBuffer.length;
                                                    try {
                                                        // Salta esos bytes restantes en el archivo
                                                        Input.Skip(i);
                                                    } catch (UtilsException ex) {
                                                        // No se pudo leer el archivo de entrada
                                                        synchronized (this) {
                                                            this.Progress = -1;
                                                        }
                                                        throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "024");
                                                    }
                                                    // Determina cuantos bytes se deben leer para completar el buffer
                                                    i = InputBuffer.length - DTemp;
                                                    // De la cantidad de bytes leidos elimino el encabezado
                                                    NumBytesReads -= i;
                                                    // Genera un subuffer para leer los datos eliminados
                                                    SubInputBuffer = new byte[i];
                                                }
                                                try {
                                                    // Lectura del archivo de entrada
                                                    DTemp = (int) Input.Read(SubInputBuffer);
                                                } catch (UtilsException ex) {
                                                    // No se pudo leer el archivo de entrada
                                                    synchronized (this) {
                                                        this.Progress = -1;
                                                    }
                                                    throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "025");
                                                }
                                                if (DTemp > 0) {
                                                    // Completa el buffer con los datos leidos
                                                    ArrayUtils.arrayCopy(SubInputBuffer, 0, InputBuffer, InputBuffer.length - DTemp, DTemp);
                                                    NumBytesReads += DTemp;
                                                }
                                                NumBlocksRead += NumBytesReads / 8;
                                                // Redimensiono el subbuffer para continuar con la codificacion
                                                SubInputBuffer = new byte[16];
                                            }
                                            // Realiza la decodificacion del buffer leido desde el archivo
                                            for (i = 0; i < NumBytesReads; i += 16) {
                                                for (j = 0; j < 16; j++) {
                                                    SubInputBuffer[j] = InputBuffer[i + j];
                                                }
                                                // Decodifica el bloque de 128 bits
                                                synchronized (AES) {
                                                    SubInputBuffer = AES.Decrypt(SubInputBuffer);
                                                }
                                                for (j = 0; j < 16; j++) {
                                                    InputBuffer[i + j] = SubInputBuffer[j];
                                                }
                                            }
                                            // Verifica si se llego al final del archivo
                                            if ((NumBytesWrite + NumBytesReads) > OutputFileLength) {
                                                //Calcula la cantidad de bytes para finalizar el archivo
                                                NumBytesReads = (int) (OutputFileLength - NumBytesWrite);
                                                //Trata de recuperar el HASH Original
                                                if (Hash != null) {
                                                    // Verifica si el hash esta cargado completo en buffer
                                                    if ((NumBytesReads + Hash.hashSize()) < InputBuffer.length) {
                                                        // El hash esta cargado en el Buffer
                                                        OrgDigest = (byte[]) ArrayUtils.subArray(InputBuffer, (int) NumBytesReads, Hash.hashSize());
                                                    } else {
                                                        // Recupera el pedazo de HASH faltante
                                                        // BufferTemporal para cargar el pedazo de hash desde el archivo en un bloque multiplo de 16
                                                        OrgDigest = new byte[(int) (16 * Math.ceil((double) ((NumBytesReads + Hash.hashSize()) - InputBuffer.length) / 16))];
                                                        try {
                                                            // Lectura del archivo de entrada
                                                            // Lectura del archivo de entrada
                                                            DTemp = (int) Input.Read(OrgDigest);
                                                        } catch (UtilsException ex) {
                                                            // No se pudo leer el archivo de entrada
                                                            synchronized (this) {
                                                                this.Progress = -1;
                                                            }
                                                            throw new UtilsException("ERROR: NO se pudo leer el archivo " + Input.getAbsoluteFilePath(), ERROR_NOREADINFILE, AESFile.CLASSID + "026");
                                                        }
                                                        // Realiza la decodificacion del buffer tempora leido desde el archivo
                                                        for (i = 0; i < DTemp; i += 16) {
                                                            for (j = 0; j < 16; j++) {
                                                                SubInputBuffer[j] = OrgDigest[i + j];
                                                            }
                                                            // Decodifica el bloque de 128 bits
                                                            synchronized (AES) {
                                                                SubInputBuffer = AES.Decrypt(SubInputBuffer);
                                                            }
                                                            for (j = 0; j < 16; j++) {
                                                                OrgDigest[i + j] = SubInputBuffer[j];
                                                            }
                                                        }
                                                        // Recupero el pedazo de hash faltante
                                                        OrgDigest = (byte[]) ArrayUtils.resizeArray(OrgDigest, (int) ((NumBytesReads + Hash.hashSize()) - InputBuffer.length));
                                                        // Redimenciono el buffer de entrada para contener el hash completo 
                                                        InputBuffer = (byte[]) ArrayUtils.resizeArray(InputBuffer, InputBuffer.length + OrgDigest.length);
                                                        // Se copia el pedazo de Hash Faltante
                                                        ArrayUtils.arrayCopy(OrgDigest, 0, InputBuffer, InputBuffer.length - OrgDigest.length, OrgDigest.length);
                                                        // Recupera el HASH
                                                        OrgDigest = (byte[]) ArrayUtils.subArray(InputBuffer, (int) NumBytesReads, Hash.hashSize());
                                                    }
                                                }
                                            }
                                            // Calcula el HASH
                                            if (Hash != null) {
                                                Hash.update(InputBuffer, 0, (int) NumBytesReads);
                                            }
                                            try {
                                                Output.Write(InputBuffer, 0, (int) NumBytesReads);
                                            } catch (UtilsException ex) {
                                                // Error de escritura del archivo de salida
                                                synchronized (this) {
                                                    this.Progress = -1;
                                                }
                                                throw new UtilsException("ERROR: NO se puede escribir en el archivo " + Output.getAbsoluteFilePath(), ERROR_WRITEOUTFILE, AESFile.CLASSID + "027");
                                            }
                                            NumBytesWrite += NumBytesReads;
                                            NumBlocksRead += NumBytesReads / 8;
                                        }
                                        // Calcula el Porcentaje de Avance en al decodificacion del Archivo
                                        if (OutputFileLength > 0) {
                                            DTemp = (int) ((NumBytesWrite * 100) / OutputFileLength);
                                        } else {
                                            DTemp = 0;
                                        }
                                        if (DTemp == 100) {
                                            DTemp = 99;
                                        }
                                        synchronized (this) {
                                            this.Progress = DTemp;
                                        }
                                    }
                                    if (Hash != null) {
                                        NewDigest = Hash.digest();
                                        if (!Arrays.equals(OrgDigest, NewDigest)) {
                                            synchronized (this) {
                                                this.Progress = -1;
                                            }
                                            throw new UtilsException("ERROR: HASH NO COINCIDEN", ERROR_HASHNOMACH, AESFile.CLASSID + "028");
                                        }
                                    }
                                    try {
                                        Input.Close();
                                    } catch (UtilsException ex) {
                                        // Error al cerrar el archivo de entrada
                                        synchronized (this) {
                                            this.Progress = -1;
                                        }
                                        throw new UtilsException("ERROR: NO se puede cerrar el archivo " + Input.getAbsoluteFilePath(), ERROR_CLOSEINFILE, AESFile.CLASSID + "029");
                                    }
                                    try {
                                        Output.Close();
                                    } catch (UtilsException ex) {
                                        // Error al cerrar el archivo de salida
                                        synchronized (this) {
                                            this.Progress = -1;
                                        }
                                        throw new UtilsException("ERROR: NO se puede cerrar el archivo " + Output.getAbsoluteFilePath(), ERROR_CLOSEOUTFILE, AESFile.CLASSID + "030");
                                    }
                                }
                            } else {
                                synchronized (this) {
                                    this.Progress = -1;
                                }
                                throw new UtilsException("ERROR: NO se pudo Decodificar el archivo " + Input.getAbsoluteFilePath(), ERROR_DECODEC, AESFile.CLASSID + "031");
                            }
                        } else {
                            synchronized (this) {
                                this.Progress = -1;
                            }
                            throw new UtilsException("ERROR: NO se pudo Decodificar el archivo " + Input.getAbsoluteFilePath(), ERROR_DECODEC, AESFile.CLASSID + "032");
                        }
                    } else if (Input.isDirectory()) {
                        // Trata de realizar la codificacion del directorio
                    } else {
                        synchronized (this) {
                            this.Progress = -1;
                        }
                        throw new UtilsException("ERROR: NO se puede identificar el tipo de archivo a codificar", ERROR_INFILETYPE, AESFile.CLASSID + "033");
                    }
                } else {
                    synchronized (this) {
                        this.Progress = -1;
                    }
                    throw new UtilsException("ERROR: Clave NO definida para codificar archivo", ERROR_PASSWD, AESFile.CLASSID + "034");
                }
            } else {
                synchronized (this) {
                    this.Progress = -1;
                }
                throw new UtilsException("ERROR: Achivo de entrada tiene tamaño 0", ERROR_INPUTFILEZEROSIZE, AESFile.CLASSID + "035");
            }
        } else {
            synchronized (this) {
                this.Progress = -1;
            }
            throw new UtilsException("ERROR: Archivos de Decodificacion NO Definidos", ERROR_FILEPARAMETERS, AESFile.CLASSID + "036");
        }
        synchronized (this) {
            this.Progress = 100;
        }
    }

    /**
     * Realiza la codificacion de un archivo, del que recibe en Input el objeto
     * que lo define, en base a la clave con la cual se inicializo el algoritmo;
     * generando el archivo codificado especificado en Output; si Output es
     * 'null' utiliza el mismo nombre del archivo de entrada y le agrega la
     * extencion .caes
     *
     * Si Output existe es borrado de forma NO SEGURA porque se presupone que si
     * existe es un archivo ya codificado.
     *
     * En opciones se especifican los parametros de configuracion del algoritmo
     * concatenados con 'or' |
     *
     * Ejemplo de Como Manejar la excepcion de no poder abrir el archivo de
     * entrada try { Salida=AESFile.Codec(Entrada,null,CuimaFile.SHA1); } catch
     * (UtilsException e) { if(e.getErrorCode()==AESFile.NOOPENINFILE){
     * System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!"); } }
     *
     * @param Input Objeto que define el archivo a codificar
     * @param Output Objeto que define el archivo codificado
     * @param Opciones Parametros de configuracion del codificador
     */
    @Override
    public synchronized void Codec(FileManager Input, FileManager Output, int Opciones) {
        MersenneTwisterPlus Random;

        if ((this.Ejecutando == null) || (this.Ejecutando.getState() == Thread.State.TERMINATED)) {
            Random = new MersenneTwisterPlus();
            this.Progress = 0;
            this.FileParameters = new FileOperationParameters(Input, Output, Opciones);
            this.Coding = true;
            this.Ejecutando = new Thread(this);
            this.Ejecutando.setName(this.CLASSID + "[" + Long.toHexString(Random.nextLong63()) + "]");
            this.Ejecutando.start();
        }
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
     * entrada try { Salida=AESFile.Codec(Entrada,null,CuimaFile.SHA1); } catch
     * (UtilsException e) { if(e.getErrorCode()==AESFile.NOOPENINFILE){
     * System.out.println("NO SE PUEDE ABRIR El ARCHIVO DE ENTRADA!!!"); } }
     *
     * @param Input Archivo a decodificar
     * @param Output Archivo de salida
     */
    @Override
    public synchronized void Decodec(FileManager Input, FileManager Output) {
        MersenneTwisterPlus Random;

        if ((this.Ejecutando == null) || (this.Ejecutando.getState() == Thread.State.TERMINATED)) {
            Random = new MersenneTwisterPlus();
            this.Progress = 0;
            this.FileParameters = new FileOperationParameters(Input, Output, 0);
            this.Coding = false;
            this.Ejecutando = new Thread(this);
            this.Ejecutando.setName(this.CLASSID + "[" + Long.toHexString(Random.nextLong63()) + "]");
            this.Ejecutando.start();
        }
    }

    @Override
    public synchronized int Progress() {
        return this.Progress;
    }

    @Override
    public synchronized boolean isDone() {
        return ((this.Progress == 100) || (this.Progress == -1));
    }

    /**
     * Recupera el codigo de Error de la Ejecucion del algoritmo
     *
     * @return Codigo de Error de la Ejecucion del Algoritmo
     */
    public synchronized int getErrorCode() {
        return ErrorCode;
    }

    /**
     * Retorna TRUE si se produjo un error en la ejecucion del algoritmo de
     * codificacion o FALSE si no.
     *
     * @return TRUE si Error o FALSE si no se produjo Error
     */
    public synchronized boolean hasError() {

        if ((this.Ejecutando != null) || (this.Ejecutando.getState() == Thread.State.TERMINATED)) {
            if (this.ErrorCode != 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retorna un manejador de archivo hacia el archivo de salida del algoritmo.
     *
     * NOTA: Si el archivo de Salida no ha sido calculado por el algoritmo
     * retorna NULL.
     *
     * @return Manejador de archivo de Salida.
     */
    public synchronized FileManager getOutputFile() {
        FileManager Salida = null;

        if (this.FileParameters != null) {
            Salida = this.FileParameters.getOutput();
            if ((Salida == null) || (Salida.isDirectory())) {
                Salida = null;
            }
        }
        return Salida;
    }

    /**
     * Ejecuta la Hebra que procesa el archivo
     */
    @Override
    public void run() {

        synchronized (this) {
            this.ErrorCode = 0;
        }
        if (this.Coding) {
            try {
                this.PrivCodec();
            } catch (UtilsException ex) {
                synchronized (this) {
                    this.ErrorCode = ex.getErrorCode();
                }
                this.BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, ex, null, AESFile.CLASSID, "037");
            }
        } else {
            try {
                this.PrivDecodec();
            } catch (UtilsException ex) {
                synchronized (this) {
                    this.ErrorCode = ex.getErrorCode();
                }
                this.BTLogF.LogMsg(LoggerManager.TYPE_ERROR, LoggerManager.LEVEL_ERROR, false, ex, null, AESFile.CLASSID, "038");
            }
        }
    }

    /**
     * Clase privada que almacena la informacion de los archivos a procesar asi
     * como las opciones a utilizar
     *
     */
    private class FileOperationParameters {

        private FileManager Input;
        private FileManager Output;
        private int Opciones;

        /**
         * Constructor por defecto
         *
         * @param Input Archivo de Entrada
         * @param Output Archivo de Salida
         * @param Opciones Parametros de configuracion del codificador
         */
        public FileOperationParameters(FileManager Input, FileManager Output, int Opciones) {
            this.Input = Input;
            this.Output = Output;
            this.Opciones = Opciones;
        }

        /**
         * Retorna el manejador del archivo de entrada
         *
         * @return Manejador del archivo de entrada
         */
        public synchronized FileManager getInput() {
            return Input;
        }

        /**
         * Establece el manejador del archivo de entrada
         *
         * @param Input Manejador del archivo de entrada
         */
        public synchronized void setInput(FileManager Input) {
            this.Input = Input;
        }

        /**
         * Retorna el manejador del archivo de salida
         *
         * @return Manejador del archivo de salida
         */
        public synchronized FileManager getOutput() {
            return Output;
        }

        /**
         * Establece el manejador del archivo de Salida
         *
         * @param Output Manejador del archivo de salida
         */
        public synchronized void setOutput(FileManager Output) {
            this.Output = Output;
        }

        /**
         * Retorna las opciones para la codificacion del archivo.
         *
         * @return Opciones para la codificacion del archivo.
         */
        public synchronized int getOpciones() {
            return Opciones;
        }

        /**
         * Establece las opciones para la codificacion del archivo.
         *
         * @param Opciones Opciones para la codificacion del archivo.
         */
        public synchronized void setOpciones(int Opciones) {
            this.Opciones = Opciones;
        }
    }
}
