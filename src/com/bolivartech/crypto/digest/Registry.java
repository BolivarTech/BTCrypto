package com.bolivartech.crypto.digest;

/**
 * A placeholder for <i>names</i> and <i>literals</i> used throughout this
 * library.
 *
 * @author Juian Bolivar
 * @since 2010
 * @version $Revision: 1.0 $
 */
public interface Registry {

    // Constants
    // -------------------------------------------------------------------------
    /** The name of our Provider. */
    String CUAIMACRYPT = "CUAIMACRYPT";
    // Names of properties to use in Maps when initialising primitives .........
    // Message digest algorithms and synonyms...................................

    /**
     *
     */
        String WHIRLPOOL_HASH = "whirlpool";

    /**
     *
     */
    String WHIRLPOOL2000_HASH = "whirlpool_2000";

    /**
     *
     */
    String WHIRLPOOL2003_HASH = "whirlpool_2003";

    /**
     *
     */
    String RIPEMD128_HASH = "ripemd128";

    /**
     *
     */
    String RIPEMD160_HASH = "ripemd160";

    /**
     *
     */
    String SHA160_HASH = "sha-160";

    /**
     *
     */
    String SHA224_HASH = "sha-224";

    /**
     *
     */
    String SHA256_HASH = "sha-256";

    /**
     *
     */
    String SHA384_HASH = "sha-384";

    /**
     *
     */
    String SHA512_HASH = "sha-512";

    /**
     *
     */
    String TIGER_HASH = "tiger";

    /**
     *
     */
    String TIGER2_HASH = "tiger2";

    /**
     *
     */
    String TIGER160_HASH = "tiger-160";

    /**
     *
     */
    String TIGER128_HASH = "tiger-128";

    /**
     *
     */
    String HAVAL_HASH = "haval";

    /**
     *
     */
    String HAS160_HASH = "has-160";

    /**
     *
     */
    String SHA0_HASH = "sha-0";

    /**
     *
     */
    String HAVAL_HASH_128_3 = "haval_128_3";

    /**
     *
     */
    String HAVAL_HASH_128_4 = "haval_128_4";

    /**
     *
     */
    String HAVAL_HASH_128_5 = "haval_128_5";

    /**
     *
     */
    String HAVAL_HASH_160_3 = "haval_160_3";

    /**
     *
     */
    String HAVAL_HASH_160_4 = "haval_160_4";

    /**
     *
     */
    String HAVAL_HASH_160_5 = "haval_160_5";

    /**
     *
     */
    String HAVAL_HASH_192_3 = "haval_192_3";

    /**
     *
     */
    String HAVAL_HASH_192_4 = "haval_192_4";

    /**
     *
     */
    String HAVAL_HASH_192_5 = "haval_192_5";

    /**
     *
     */
    String HAVAL_HASH_224_3 = "haval_224_3";

    /**
     *
     */
    String HAVAL_HASH_224_4 = "haval_224_4";

    /**
     *
     */
    String HAVAL_HASH_224_5 = "haval_224_5";

    /**
     *
     */
    String HAVAL_HASH_256_3 = "haval_256_3";

    /**
     *
     */
    String HAVAL_HASH_256_4 = "haval_256_4";

    /**
     *
     */
    String HAVAL_HASH_256_5 = "haval_256_5";

    /**
     *
     */
    String MD5_HASH = "md5";

    /**
     *
     */
    String MD4_HASH = "md4";

    /**
     *
     */
    String MD2_HASH = "md2";
    /** RIPEMD-128 is synonymous to RIPEMD128. */
    String RIPEMD_128_HASH = "ripemd-128";
    /** RIPEMD-160 is synonymous to RIPEMD160. */
    String RIPEMD_160_HASH = "ripemd-160";
    /** SHA-1 is synonymous to SHA-160. */
    String SHA_1_HASH = "sha-1";
    /** SHA1 is synonymous to SHA-160. */
    String SHA1_HASH = "sha1";
    /** SHA is synonymous to SHA-160. */
    String SHA_HASH = "sha";

    /**
     *
     */
    String CRC32_HASH = "crc32";

    /**
     *
     */
    String CRC64_HASH = "crc64";
}
