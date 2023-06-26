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
import com.bolivartech.crypto.interfaces.CryptoBinary;
import com.bolivartech.utils.array.ArrayUtils;
import com.bolivartech.utils.converters.Converter;
import com.bolivartech.utils.exception.UtilsException;
import com.bolivartech.utils.random.MersenneTwisterPlus;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Copyright 2007,2009,2010,2011,2012,2013,2014,2015,2016 BolivarTech C.A.
 *
 *  <p>Homepage: <a href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.</p>
 *  <p>BolivarTech Homepage: <a href="http://www.bolivartech.com">http://www.bolivartech.com</a>.</p>
 *
 *   This Class is the CuaimaCrypt's util for code Text data.
 *
 *   Realiza la codificacion y decodificacion de una cadena de caracteres basado en
 *   un password de 1 caracteres minimos, retornando una cadena encriptada y codificada
 *   en Base64
 *
 * Class ID: "TR74ID1" 
 * Loc: 000-007
 * 
 * @author Julian Bolivar
 * @since 2007 - March 25, 2016.
 * @version 3.0.2
 * 
 * <p>
 * Change Log:
 * </p>
 * <ul>
 * <li>v3.0.2 (2016-03-25) Se agrego el codigo de localizacion para la excepcion y bitacoras.</li>
 * <li>v3.0.1 - Se forza la utilizacion del US-ASCII para las marcas del encabezado.</li>
 * <li>v3.0.0 - Se realiza la estandarizacion de la mascara para el control de Versiones.</li>
 * <li>v2.1.0 - Se Agrego Soporte de Hash para verificar que el binario fue codificado correctarmente.</li>
 * <li>v2.0.0 - The Random generator is initializated using the new class
 * MersenneTwisterPlus that was implemente by BolivarTech.</li>
 * </ul>
 */
public class CuaimaBinary implements CryptoBinary {
    
    // Codigo de identificacion de la clase
    private static final String CLASSID = "TR74ID1";

    private CuaimaCrypt CCPT;
    private int PasswdLength;
    private double HeadPos;
    
    /** Version del algoritmo CuaimaCryptBinary (NOTA: Maximo hasta 255 porque son solo 8 bits)  */
    private final static short VERSION = 3;
    
    /** Mascara para recuperar el valor del algoritmo de HASH  */
    private final static int HASHMASK = 62;
    
    /****** Seleccion de Causas de Error del Algoritmo para las Exepciones *******/
    /** La cantidad de bloques es menor a 2 para inicializar el algoritmo  */
    public final static int ERROR_NUMBLCK = -3;
    

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
    }

    /**
     * Constructor por defecto de CuaimaText, utilizando 9 bloques de RakeCodecs
     */
    public CuaimaBinary() {

        PasswdLength = -1;
        CCPT = new CuaimaCrypt();
    }

    /**
     * Constructor con inicializacion del numero de bloques de RakeCodecs a
     * utilizar por CuaimaCrypt.
     * El minimo numero de bloques de RakeCodecs es 2.
     *
     * @param NumBlocks
     * @throws UtilsException
     */
    public CuaimaBinary(int NumBlocks) throws UtilsException {

        PasswdLength = -1;
        if (NumBlocks >= 2) {
            CCPT = new CuaimaCrypt(NumBlocks);
        } else {
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaText, la cantidad de bloques es menor a 2", ERROR_NUMBLCK,CuaimaBinary.CLASSID+"000");
        }
    }

    /**
     * Constructor con inicializacion del password de CuaimaText, utilizando 9 bloques
     * de RakeCodecs
     *
     * @param Password
     * @throws UtilsException
     */
    public CuaimaBinary(String Password) throws UtilsException {

        CCPT = new CuaimaCrypt();
        if (CCPT.Password(Password) != 0) {
            PasswdLength = -1;
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaText, falla al inicializar el Password", ERROR_PASSWD,CuaimaBinary.CLASSID+"001");
        } else {
            PasswdLength = Password.length();
            this.CalcHeadPos(Password);
        }
    }

    /**
     * Constructor con inicializacion del password de CuaimaText, utilizando la cantidad
     * de bloques de RakeCodecs especificada en NumBlocks
     *
     * @param Password
     * @param NumBlocks
     * @throws UtilsException
     */
    public CuaimaBinary(String Password, int NumBlocks) throws UtilsException {

        if (NumBlocks >= 2) {
            CCPT = new CuaimaCrypt(NumBlocks);
        } else {
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaText, la cantidad de bloques es menor a 2", ERROR_NUMBLCK,CuaimaBinary.CLASSID+"002");
        }
        if (CCPT.Password(Password) != 0) {
            PasswdLength = -1;
            throw new UtilsException("ERROR: NO se pudo inicializar CuaimaText, falla al inicializar con el Password", ERROR_PASSWD,CuaimaBinary.CLASSID+"003");
        } else {
            PasswdLength = Password.length();
            this.CalcHeadPos(Password);
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
        boolean salida;

        salida = false;
        PasswdLength = -1;
        if (CCPT != null) {
            if (CCPT.Password(Passw) != 0) {
                throw new UtilsException("ERROR: NO se pudo inicializar la clave en CuaimaText", ERROR_PASSWD,CuaimaBinary.CLASSID+"004");
            } else {
                PasswdLength = Passw.length();
                this.CalcHeadPos(Passw);
                salida = true;
            }
        }
        return salida;
    }

    /**
     * Reinicia los ShiftCodecs a las semillas iniciales de los mismos
     */
    public void Reset() {
        if (PasswdLength > 0) {
            CCPT.Reset();
        }
    }

    /**
     * Realiza la codificacion de una cadena de caracteres que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo
     *
     * En opciones se especifican los parametros de configuracion del algoritmo
     * concatenados con 'or' |
     *
     * Retorna null si no logro codificar la entrada
     *
     * @param Input
     * @param Opciones
     * @return Entrada codificada
     * @throws UtilsException
     */
    @Override
    public byte[] Codec(byte[] Input, int Opciones) throws UtilsException {
        byte[] Salida = null;
        MersenneTwisterPlus Rand;
        long Header[];
        long CodecBuffer[];
        long HPosc;
        long BufferPost;
        byte[] k = null;
        long A[];
        int i, j;
        double Temp;
        int HashType;
        BaseHash Hash;
        byte[] Digest;

        // Verifica si el algoritmo fue inicializado
        if (PasswdLength > 0) {
            Rand = new MersenneTwisterPlus();
            CCPT.Reset();
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
            if (HashType != NO_HASH) {
                // Calcula el HASH del mensaje Original
                //Digest = StringUtils.toString(Hash.Hash(Input));
                k = Hash.Hash(Input);
                Digest = new byte[Input.length];
                ArrayUtils.arrayCopy(Input, 0, Digest, 0, Input.length);
                Digest = (byte[]) ArrayUtils.resizeArray(Digest, Digest.length+Hash.hashSize());
                j=0;
                for(i=Digest.length-Hash.hashSize();i<Digest.length;i++){
                    Digest[i]=k[j];
                    j++;
                }
            } else {
                Digest = new byte[Input.length];
                ArrayUtils.arrayCopy(Input, 0, Digest, 0, Input.length);
            }
            // Genera el Encabezado
            Header = new long[4];
            Header[0] = (Rand.nextLong() << 32) | (Converter.byte2long(new String("CCPTTPCC").getBytes(StandardCharsets.US_ASCII))[0] >>> 32);  // BYTES de OFUSCACION
            Header[1] = (Converter.byte2long(new String("CCPTTPCC").getBytes(StandardCharsets.US_ASCII))[0] << 32) | (Rand.nextLong() >>> 32);  // BYTES de OFUSCACION
            Header[2] = (long) Input.length;
            Header[3] = Rand.nextLong() << 32;  // BYTES de OFUSCACION
            Header[3] |= HashType << 26;  // Hash usado en el mensaje
            Header[3] |= VERSION & 0xFF;    // VERSION DE CUAIMABINARY
            // Genera los Buffers para codificacion
            CodecBuffer = new long[(int) ((double) (Header.length + (2 * Math.ceil((double) Math.ceil(((double) Digest.length / 8)) / 2))))];
            // Calcula la posicion del Header en el correo
            Temp = ((double) HeadPos);
            Temp *= CodecBuffer.length;
            HPosc = (long) Temp;
            HPosc = (long) (2 * Math.ceil((double) HPosc / 2));
            if ((CodecBuffer.length - HPosc) < Header.length) {
                HPosc = CodecBuffer.length - Header.length;
            }
            // Coloca El Encabezado
            for (i = 0; i < Header.length; i++) {
                CodecBuffer[(int) (HPosc + i)] = Header[i];
            }
            //	Carga El Buffer de Codificacion con el resto de los datos
            k = new byte[8];
            BufferPost = HPosc + Header.length;
            for (i = Header.length; i < CodecBuffer.length; i++) {
                if (BufferPost == CodecBuffer.length) {
                    BufferPost = 0;
                }
                for (j = 0; j < 8; j++) {
                    if ((8 * (i - Header.length) + j) < Digest.length) {
                        k[j] = (byte) Digest[((int) (8 * (i - Header.length) + j))];
                    } else {
                        k[j] = Rand.nextByte();
                    }
                }
                A = Converter.byte2long(k);
                CodecBuffer[(int) BufferPost] = A[0];
                BufferPost++;
            }
            // Codifica el Buffer de Salida
            A = new long[2];
            BufferPost = HPosc;
            for (i = 0; i < CodecBuffer.length; i += 2) {
                if (BufferPost == CodecBuffer.length) {
                    BufferPost = 0;
                }
                A[0] = CodecBuffer[(int) BufferPost];
                A[1] = CodecBuffer[(int) BufferPost + 1];
                CCPT.Codec(A);
                CodecBuffer[(int) BufferPost] = A[0];
                CodecBuffer[(int) BufferPost + 1] = A[1];
                BufferPost += 2;
            }
            // Convierte el mensaje encryptado en arreglo de bytes
            Salida = Converter.long2byte(CodecBuffer);
        } else {
            throw new UtilsException("ERROR: NO se puede codificar el texto porque no se ha establecido una Password", ERROR_PASSWD,CuaimaBinary.CLASSID+"005");
        }
        return Salida;
    }

    /**
     * Realiza la decodificacion de una cadena de caracteres que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo.
     *
     * Si no logra decodificarlo retorna una cadena null.
     *
     * Ejemplo de Como Manejar la excepcion de que el Hash No Concuerda
     *  try {
     *       Salida=CuaimaText.Decodec(Entrada);
     *   } catch (UtilsException e) {
     *       if(e.getErrorCode()==CuaimaText.HASHNOMACH){
     *          System.out.println("HASH NO CONCUERDA!!!");
     *       }
     *   }
     *
     * @param Input
     * @return Entrada decodificada
     * @throws UtilsException
     */
    @Override
    public byte[] Decodec(byte[] Input) throws UtilsException {
        byte[] Salida = null;
        long DecodecBuffer[] = null;
        long[] Header, HTemp;
        String HeaderDec;
        long A[];
        long HPosc, BufferPost;
        double Temp;
        int i;
        int Version;
        byte[] OutBuffer;
        int HashType;
        BaseHash Hash;
        byte[] OrgDigest = null;
        byte[] NewDigest = null;

        // Verifica si el algoritmo fue inicializado
        if (PasswdLength > 0) {
            CCPT.Reset();
            HashType = 0;
            // Decodifica el mensaje de Base64
            DecodecBuffer = Converter.byte2long(Input);
            // Genera el Encabezado
            Header = new long[4];
            // Calcula la posicion del Header en el correo
            Temp = ((double) HeadPos);
            Temp *= DecodecBuffer.length;
            HPosc = (long) Temp;
            HPosc = (long) (2 * Math.ceil((double) HPosc / 2));
            if ((DecodecBuffer.length - HPosc) < Header.length) {
                HPosc = DecodecBuffer.length - Header.length;
            }
            // Decodifica el Buffer de Salida
            A = new long[2];
            BufferPost = HPosc;
            for (i = 0; i < DecodecBuffer.length; i += 2) {
                if (BufferPost == DecodecBuffer.length) {
                    BufferPost = 0;
                }
                A[0] = DecodecBuffer[(int) BufferPost];
                A[1] = DecodecBuffer[(int) BufferPost + 1];
                CCPT.Decodec(A);
                DecodecBuffer[(int) BufferPost] = A[0];
                DecodecBuffer[(int) BufferPost + 1] = A[1];
                BufferPost += 2;
            }
            // Recupera El Encabezado
            for (i = 0; i < Header.length; i++) {
                Header[i] = DecodecBuffer[(int) (HPosc + i)];
            }
            // Trata de Recuperar Informacion del Encabezado
            HTemp = new long[1];
            HTemp[0] = (Header[0] << 32) | (Header[1] >>> 32);
            HeaderDec = new String(Converter.long2byte(HTemp),StandardCharsets.US_ASCII);
            // Verifica si se pudo recuperar la informacion
            if (HeaderDec.contentEquals(new StringBuffer("CCPTTPCC"))) {
                // Recupera la Version de CuaimaText
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
                    // Genera el buffer de salida
                    if (Hash != null) {
                        OutBuffer = new byte[(((int) Header[2]) + Hash.hashSize())];
                    } else {
                        OutBuffer = new byte[((int) Header[2])];
                    }
                    // Recupera la Informacion del Buffer decodificado
                    BufferPost = HPosc + Header.length;
                    for (i = 0; i < OutBuffer.length; i+=8) {
                        if (BufferPost == DecodecBuffer.length) {
                            BufferPost = 0;
                        }
                        HTemp[0] = DecodecBuffer[(int) BufferPost];
                         ArrayUtils.arrayCopy(Converter.long2byte(HTemp), 0, OutBuffer, i, 8);
                        //OutBuffer.append(new String(Converter.long2byte(HTemp)));
                        BufferPost++;
                    }
                    if (Hash != null) {
                        OrgDigest =  (byte[]) ArrayUtils.subArray(OutBuffer,(int) Header[2],Hash.hashSize());
                    }
                    OutBuffer = (byte[]) ArrayUtils.resizeArray(OutBuffer,(int) Header[2]);
                    Salida = new byte[OutBuffer.length];
                    ArrayUtils.arrayCopy(OutBuffer, 0, Salida, 0, OutBuffer.length);
                    if (Hash != null) {
                        NewDigest = Hash.Hash(OutBuffer);
                        if (!Arrays.equals(OrgDigest,NewDigest)){
                            Salida = null;
                            throw new UtilsException("ERROR: HASH NO COINCIDEN", ERROR_HASHNOMACH,CuaimaBinary.CLASSID+"006");
                        }
                    }
                } else {
                    throw new UtilsException("ERROR: Version de CuaimaText NO Reconocida", ERROR_VERSION,CuaimaBinary.CLASSID+"007");
                }
            }
        }
        return Salida;
    }
  
}
