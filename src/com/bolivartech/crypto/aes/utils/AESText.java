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
import com.bolivartech.crypto.interfaces.CryptoText;
import com.bolivartech.utils.array.ArrayUtils;
import com.bolivartech.utils.converters.Base64;
import com.bolivartech.utils.converters.Converter;
import com.bolivartech.utils.exception.UtilsException;
import com.bolivartech.utils.random.MersenneTwisterPlus;
import java.io.IOException;
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
 * Class ID: "TR74ID4" 
 * Loc: 000-007
 * 
 * @author Julian Bolivar
 * @since 2007 | 2016-03-25
 * @version 2.0.1
 * 
 * <p>
 * Change Log:
 * </p>
 * <ul>
 * <li>v2.0.1 (2016-03-25) Se agrego el codigo de localizacion para la excepcion
 * y bitacoras.</li>
 * </ul>
 */
public class AESText implements CryptoText {
    
    // Codigo de identificacion de la clase
    private static final String CLASSID = "TR74ID4";

    private CuaimaAES AES;
    private int PasswdLength;
    private double HeadPos;
    private int LineLength = 76;
    
    /** Mascara para recuperar el valor del algoritmo de HASH  */
    private final static int HASHMASK = 62;
    
    /**
     * La cantidad de caracteres es menor a 2 para formatear la salida
     */
    public final static int ERROR_NUMCHARLESS2 = -3;
    
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
     * Constructor por defecto de AESText
     */
    public AESText() {

        PasswdLength = -1;
        AES = new CuaimaAES();
    }


    /**
     * Constructor con inicializacion del password de AESText.
     *
     * @param Password
     * @throws UtilsException
     */
    public AESText(String Password) throws UtilsException {

        AES = new CuaimaAES();
        if (AES.Password(Password) != 0) {
            PasswdLength = -1;
            throw new UtilsException("ERROR: NO se pudo inicializar AESText, falla al inicializar el Password", ERROR_PASSWD,AESText.CLASSID+"000");
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
     * Establece la clave que utiliza AESText para codificar el texto, la
     * cual debe de tener como minimo un caracter de longitud
     * 
     * @param Passw Password a utilizar
     * @return true si lo logro y false si no
     * @throws UtilsException Excepcion de establecimiento de clave
     */
    @Override
    public boolean Password(String Passw) throws UtilsException {
        boolean salida;

        salida = false;
        PasswdLength = -1;
        if (AES != null) {
            if (AES.Password(Passw) != 0) {
                throw new UtilsException("ERROR: NO se pudo inicializar la clave en AESText", ERROR_PASSWD,AESText.CLASSID+"001");
            } else {
                PasswdLength = Passw.length();
                this.CalcHeadPos(Passw);
                salida = true;
            }
        }
        return salida;
    }

    /**
     * Realiza la codificacion de una cadena de caracteres que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo
     *
     * En opciones se especifican los parametros de configuracion del algoritmo
     * concatenados con 'or' |
     *
     * Retorna null si no logro codificar la entrada.
     * 
     * NOTA: El String de entrada debe estas codificado en UTF16
     *
     * @param Input Strign a codificar
     * @param Opciones Opciones de codificacion
     * @return Entrada codificada
     * @throws UtilsException Excepciones de codificacion
     */
    @Override
    public String Codec(String Input, int Opciones) throws UtilsException {
        String Salida = null;
        MersenneTwisterPlus Rand;
        long Header[];
        long CodecBuffer[];
        long HPosc;
        long BufferPost;
        long MessageLength;
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
                Digest = Input.getBytes(StandardCharsets.UTF_16);
                MessageLength = (long)Digest.length;
                k = Hash.Hash(Digest);
                Digest = (byte[]) ArrayUtils.resizeArray(Digest, Digest.length+Hash.hashSize());
                j=0;
                for(i=Digest.length-Hash.hashSize();i<Digest.length;i++){
                    Digest[i]=k[j];
                    j++;
                }
            } else {
                Digest = Input.getBytes(StandardCharsets.UTF_16);
                MessageLength = (long)Digest.length;
            }
            // Genera el Encabezado
            Header = new long[4];
            Header[0] = (Rand.nextLong() << 32) | (Converter.byte2long(new String("CAESSEAC").getBytes())[0] >>> 32);  // BYTES de OFUSCACION
            Header[1] = (Converter.byte2long(new String("CAESSEAC").getBytes())[0] << 32) | (Rand.nextLong() >>> 32);  // BYTES de OFUSCACION
            Header[2] = MessageLength;
            Header[3] = Rand.nextLong() << 32;  // BYTES de OFUSCACION
            Header[3] |= HashType << 26;  // Hash usado en el mensaje
            Header[3] |= 1L;    // VERSION DE CUAIMATEXT
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
            //	Carga El Buffer de Codificacion con el resto del email
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
                k=Converter.long2byte(A);
                k=AES.Encrypt(k);
                A=Converter.byte2long(k);
                CodecBuffer[(int) BufferPost] = A[0];
                CodecBuffer[(int) BufferPost + 1] = A[1];
                BufferPost += 2;
            }
            try {
                // Codifica el mensaje encriptado a Base64
                Salida = Base64.encodeBytes(Converter.long2byte(CodecBuffer), Base64.URL_SAFE);
                if ((Opciones & AESText.BREAK_LINES) == AESText.BREAK_LINES) {
                    Salida = this.LineBreak(Salida);
                }
            } catch (IOException ex) {
                throw new UtilsException("ERROR: NO se puede codificar el texto a Base64", ERROR_BASE64CODEC,AESText.CLASSID+"002");
                //Logger.getLogger(AESText.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            throw new UtilsException("ERROR: NO se puede codificar el texto porque no se ha establecido una Password", ERROR_PASSWD,AESText.CLASSID+"003");
        }
        return Salida;
    }

    /**
     * Realiza la decodificacion de una cadena de caracteres que recibe en Input en
     * base a la clave con la cual se inicializo el algoritmo.
     *
     * Si no logra decodificarlo retorna una cadena null.
     * 
     * NOTA: El String de salida esta codificado en UTF16
     *
     * Ejemplo de Como Manejar la excepcion de que el Hash No Concuerda
     *  try {
     *       Salida=AESText.Decodec(Entrada);
     *   } catch (UtilsException e) {
     *       if(e.getErrorCode()==AESText.HASHNOMACH){
     *          System.out.println("HASH NO CONCUERDA!!!");
     *       }
     *   }
     *
     * @param Input Entrada a decodificar
     * @return Entrada decodificada
     * @throws UtilsException Excepcion de decodificacion
     */
    @Override
    public String Decodec(String Input) throws UtilsException {
        String Salida = null;
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
        byte[] k;

        // Verifica si el algoritmo fue inicializado
        if (PasswdLength > 0) {
            HashType = 0;
            try {
                // Elimina caracteres no deseados
                Input = TrimMessage(Input);
                // Decodifica el mensaje de Base64
                DecodecBuffer = Converter.byte2long(Base64.decode(Input, Base64.URL_SAFE));
            } catch (IOException ex) {
                throw new UtilsException("ERROR: NO se puede decodificar el texto en Base64", ERROR_BASE64DECODEC,AESText.CLASSID+"004");
                //Logger.getLogger(AESText.class.getName()).log(Level.SEVERE, null, ex);
            }
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
                k=Converter.long2byte(A);
                k=AES.Decrypt(k);
                A=Converter.byte2long(k);
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
            HeaderDec = new String(Converter.long2byte(HTemp));
            // Verifica si se pudo recuperar la informacion
            if (HeaderDec.contentEquals(new StringBuffer("CAESSEAC"))) {
                // Recupera la Version de AESText
                Version = (int) (Header[3] & 0x0000000000000001);
                if (Version == 1) {
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
                    Salida = new String(OutBuffer,StandardCharsets.UTF_16);
                    if (Hash != null) {
                        NewDigest = Hash.Hash(OutBuffer);
                        if (!Arrays.equals(OrgDigest,NewDigest)){
                            Salida = null;
                            throw new UtilsException("ERROR: HASH NO COINCIDEN", ERROR_HASHNOMACH,AESText.CLASSID+"005");
                        }
                    }
                } else {
                    throw new UtilsException("ERROR: Version de AESText NO Reconocida", ERROR_VERSION,AESText.CLASSID+"006");
                }
            }
        }
        return Salida;
    }

    /**
     * Elimina todos los saltos de linea y espacios en blanco dentro del mensaje
     *
     * @return String
     */
    private String TrimMessage(String Entrada) {

        Entrada = Entrada.trim();
        Entrada = Entrada.replace("\n", "");
        Entrada = Entrada.replace(" ", "");
        return Entrada;
    }

    /**
     * Realiza la separacion de una cadena de caracteres que recibe en Input en
     * base a la cantidad de caracteres por linea.
     *
     * Las salida es formateada con la cantidad de caracteres por linea especificada,
     * la cantidad por defecto es 76
     *
     * Retorna null si no logro codificar la entrada
     *
     * @param Input
     * @return Entrada separada en lineas
     * @throws UtilsException
     */
    private String LineBreak(String Input) throws UtilsException {
        StringBuffer Separador;
        int i;

        Separador = new StringBuffer(Input);
        if (this.LineLength > 1) {
            for (i = this.LineLength; i < Separador.length(); i += this.LineLength + 1) {
                Separador = Separador.insert(i, "\n");
            }
        } else {
            throw new UtilsException("WARNING: La longitud de las lineas codificadas es menos a dos caracteres",AESText.ERROR_NUMCHARLESS2,AESText.CLASSID+"007");
        }
        Separador.trimToSize();
        return Separador.toString();
    }

    /**
     * Retorna la cantidad de caracteres que tiene cada linea en el mensaje.
     *
     * @return la longitud maxima de una linea del mensaje
     */
    @Override
    public int getLineLength() {
        return LineLength;
    }

    /**
     * Establece la cantidad de caracteres que contiene cada linea del mensaje.
     *
     * El valor estandar es de 76 caracteres por linea
     * 
     * @param LineLength Longitud de la linea generada
     */
    @Override
    public void setLineLength(int LineLength) {

        if (LineLength > 1) {
            this.LineLength = LineLength;
        }
    }
}
