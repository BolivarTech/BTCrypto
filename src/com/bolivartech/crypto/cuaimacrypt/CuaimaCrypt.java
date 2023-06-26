package com.bolivartech.crypto.cuaimacrypt;

import com.bolivartech.utils.random.KAOSrand;
import com.bolivartech.utils.random.sparkers.PasswordSparker;

/**
 * Copyright 2007,2009,2010,2011,2012,2013,2014 BolivarTech C.A.
 * 
 * <p>
 * Homepage: <a
 * href="http://www.cuaimacrypt.com">http://www.cuaimacrypt.com</a>.
 * </p>
 * <p>
 * BolivarTech Homepage: <a
 * href="http://www.bolivartech.com">http://www.bolivartech.com</a>.
 * </p>
 * 
 * This Class is the CuaimaCrypt's core.
 * 
 * 
 * Realiza la codificacion y decodificacion de dos palabras de 64 bits basado en
 * un password de 1 caracteres minimos
 * 
 * 
 * @author Julian Bolivar
 * @version 3.1.0
 * 
 *          <p>
 *          Change Log:
 *          </p>
 *          <ul>
 *          <li>v3.1.0 - Optimization at Seed Hopping Definition.</li>
 *          <li>v3.0.1 - The password used new Random.nextInt(number).</li>
 *          <li>v3.0.0 - Se realiza la estandarizacion del generador de llaves
 *          para usar la clase KaosRand y PasswordSparker de BolivarTech Utils.
 *          Minor Speed Optimizations.</li>
 *          <li>v2.1.0 - Los ciclos de inicializacion de las semillas con el
 *          password se bajaron a 9 para la compatibilidad con la version movil</li>
 *          <li>v2.0.0 - The Random generator is initializated using the new
 *          class MersenneTwisterPlus that was implemente by BolivarTech.</li>
 *          </ul>
 */
public class CuaimaCrypt {

	// Generador de numeros aleatorios
	private KAOSrand RLorenz;

	private RakeCodec RCA[];
	private int CrossBitsSecuen[];
	private int SeedHoppingSeq[];
	private long WalshCodes[][];
	private int WalshCode;

	/**
	 * Inicializa los codigos Walsh a utilizar en el spread de los datos
	 */
	private void InitWalshCode() {

		WalshCodes = new long[128][2];
		WalshCodes[0][0] = 0L;
		WalshCodes[1][0] = -3074457345618260000L;
		WalshCodes[2][0] = -5534023222112870000L;
		WalshCodes[3][0] = 7378697629483820000L;
		WalshCodes[4][0] = -8138269444283630000L;
		WalshCodes[5][0] = 6510615555426900000L;
		WalshCodes[6][0] = 4340410370284600000L;
		WalshCodes[7][0] = -1627653888856720000L;
		WalshCodes[8][0] = -9151594822560190000L;
		WalshCodes[9][0] = 6172840429334710000L;
		WalshCodes[10][0] = 3732415143318660000L;
		WalshCodes[11][0] = -1830318964512040000L;
		WalshCodes[12][0] = 1148435428713440000L;
		WalshCodes[13][0] = -2691645536047110000L;
		WalshCodes[14][0] = -4844961964884800000L;
		WalshCodes[15][0] = 7608384715226510000L;
		WalshCodes[16][0] = -9223090566172970000L;
		WalshCodes[17][0] = 6149008514797120000L;
		WalshCodes[18][0] = 3689517697151000000L;
		WalshCodes[19][0] = -1844618113234590000L;
		WalshCodes[20][0] = 1085350949055100000L;
		WalshCodes[21][0] = -2712673695933230000L;
		WalshCodes[22][0] = -4882812652679810000L;
		WalshCodes[23][0] = 7595767819294840000L;
		WalshCodes[24][0] = 72056494543077100L;
		WalshCodes[25][0] = -3050438514103900000L;
		WalshCodes[26][0] = -5490789325387020000L;
		WalshCodes[27][0] = 7393108928392440000L;
		WalshCodes[28][0] = -8074690184392680000L;
		WalshCodes[29][0] = 6531808642057220000L;
		WalshCodes[30][0] = 4378557926219170000L;
		WalshCodes[31][0] = -1614938036878540000L;
		WalshCodes[32][0] = -9223372032559810000L;
		WalshCodes[33][0] = 6148914692668170000L;
		WalshCodes[34][0] = 3689348817318890000L;
		WalshCodes[35][0] = -1844674406511960000L;
		WalshCodes[36][0] = 1085102596360830000L;
		WalshCodes[37][0] = -2712756480164650000L;
		WalshCodes[38][0] = -4882961664296370000L;
		WalshCodes[39][0] = 7595718148755990000L;
		WalshCodes[40][0] = 71777218556133100L;
		WalshCodes[41][0] = -3050531606099550000L;
		WalshCodes[42][0] = -5490956890979190000L;
		WalshCodes[43][0] = 7393053073195050000L;
		WalshCodes[44][0] = -8074936604381160000L;
		WalshCodes[45][0] = 6531726502061060000L;
		WalshCodes[46][0] = 4378410074226080000L;
		WalshCodes[47][0] = -1614987320876230000L;
		WalshCodes[48][0] = 281474976645120L;
		WalshCodes[49][0] = -3074363520626040000L;
		WalshCodes[50][0] = -5533854337126880000L;
		WalshCodes[51][0] = 7378753924479150000L;
		WalshCodes[52][0] = -8138021084010120000L;
		WalshCodes[53][0] = 6510698342184740000L;
		WalshCodes[54][0] = 4340559386448710000L;
		WalshCodes[55][0] = -1627604216802020000L;
		WalshCodes[56][0] = -9151315538050290000L;
		WalshCodes[57][0] = 6172933524171350000L;
		WalshCodes[58][0] = 3732582714024600000L;
		WalshCodes[59][0] = -1830263107610060000L;
		WalshCodes[60][0] = 1148681856222170000L;
		WalshCodes[61][0] = -2691563393544200000L;
		WalshCodes[62][0] = -4844814108379560000L;
		WalshCodes[63][0] = 7608434000728250000L;
		WalshCodes[64][0] = 0L;
		WalshCodes[65][0] = -3074457345618260000L;
		WalshCodes[66][0] = -5534023222112870000L;
		WalshCodes[67][0] = 7378697629483820000L;
		WalshCodes[68][0] = -8138269444283630000L;
		WalshCodes[69][0] = 6510615555426900000L;
		WalshCodes[70][0] = 4340410370284600000L;
		WalshCodes[71][0] = -1627653888856720000L;
		WalshCodes[72][0] = -9151594822560190000L;
		WalshCodes[73][0] = 6172840429334710000L;
		WalshCodes[74][0] = 3732415143318660000L;
		WalshCodes[75][0] = -1830318964512040000L;
		WalshCodes[76][0] = 1148435428713440000L;
		WalshCodes[77][0] = -2691645536047110000L;
		WalshCodes[78][0] = -4844961964884800000L;
		WalshCodes[79][0] = 7608384715226510000L;
		WalshCodes[80][0] = -9223090566172970000L;
		WalshCodes[81][0] = 6149008514797120000L;
		WalshCodes[82][0] = 3689517697151000000L;
		WalshCodes[83][0] = -1844618113234590000L;
		WalshCodes[84][0] = 1085350949055100000L;
		WalshCodes[85][0] = -2712673695933230000L;
		WalshCodes[86][0] = -4882812652679810000L;
		WalshCodes[87][0] = 7595767819294840000L;
		WalshCodes[88][0] = 72056494543077100L;
		WalshCodes[89][0] = -3050438514103900000L;
		WalshCodes[90][0] = -5490789325387020000L;
		WalshCodes[91][0] = 7393108928392440000L;
		WalshCodes[92][0] = -8074690184392680000L;
		WalshCodes[93][0] = 6531808642057220000L;
		WalshCodes[94][0] = 4378557926219170000L;
		WalshCodes[95][0] = -1614938036878540000L;
		WalshCodes[96][0] = -9223372032559810000L;
		WalshCodes[97][0] = 6148914692668170000L;
		WalshCodes[98][0] = 3689348817318890000L;
		WalshCodes[99][0] = -1844674406511960000L;
		WalshCodes[100][0] = 1085102596360830000L;
		WalshCodes[101][0] = -2712756480164650000L;
		WalshCodes[102][0] = -4882961664296370000L;
		WalshCodes[103][0] = 7595718148755990000L;
		WalshCodes[104][0] = 71777218556133100L;
		WalshCodes[105][0] = -3050531606099550000L;
		WalshCodes[106][0] = -5490956890979190000L;
		WalshCodes[107][0] = 7393053073195050000L;
		WalshCodes[108][0] = -8074936604381160000L;
		WalshCodes[109][0] = 6531726502061060000L;
		WalshCodes[110][0] = 4378410074226080000L;
		WalshCodes[111][0] = -1614987320876230000L;
		WalshCodes[112][0] = 281474976645120L;
		WalshCodes[113][0] = -3074363520626040000L;
		WalshCodes[114][0] = -5533854337126880000L;
		WalshCodes[115][0] = 7378753924479150000L;
		WalshCodes[116][0] = -8138021084010120000L;
		WalshCodes[117][0] = 6510698342184740000L;
		WalshCodes[118][0] = 4340559386448710000L;
		WalshCodes[119][0] = -1627604216802020000L;
		WalshCodes[120][0] = -9151315538050290000L;
		WalshCodes[121][0] = 6172933524171350000L;
		WalshCodes[122][0] = 3732582714024600000L;
		WalshCodes[123][0] = -1830263107610060000L;
		WalshCodes[124][0] = 1148681856222170000L;
		WalshCodes[125][0] = -2691563393544200000L;
		WalshCodes[126][0] = -4844814108379560000L;
		WalshCodes[127][0] = 7608434000728250000L;
		WalshCodes[0][1] = 0L;
		WalshCodes[1][1] = -3074457345618260000L;
		WalshCodes[2][1] = -5534023222112870000L;
		WalshCodes[3][1] = 7378697629483820000L;
		WalshCodes[4][1] = -8138269444283630000L;
		WalshCodes[5][1] = 6510615555426900000L;
		WalshCodes[6][1] = 4340410370284600000L;
		WalshCodes[7][1] = -1627653888856720000L;
		WalshCodes[8][1] = -9151594822560190000L;
		WalshCodes[9][1] = 6172840429334710000L;
		WalshCodes[10][1] = 3732415143318660000L;
		WalshCodes[11][1] = -1830318964512040000L;
		WalshCodes[12][1] = 1148435428713440000L;
		WalshCodes[13][1] = -2691645536047110000L;
		WalshCodes[14][1] = -4844961964884800000L;
		WalshCodes[15][1] = 7608384715226510000L;
		WalshCodes[16][1] = -9223090566172970000L;
		WalshCodes[17][1] = 6149008514797120000L;
		WalshCodes[18][1] = 3689517697151000000L;
		WalshCodes[19][1] = -1844618113234590000L;
		WalshCodes[20][1] = 1085350949055100000L;
		WalshCodes[21][1] = -2712673695933230000L;
		WalshCodes[22][1] = -4882812652679810000L;
		WalshCodes[23][1] = 7595767819294840000L;
		WalshCodes[24][1] = 72056494543077100L;
		WalshCodes[25][1] = -3050438514103900000L;
		WalshCodes[26][1] = -5490789325387020000L;
		WalshCodes[27][1] = 7393108928392440000L;
		WalshCodes[28][1] = -8074690184392680000L;
		WalshCodes[29][1] = 6531808642057220000L;
		WalshCodes[30][1] = 4378557926219170000L;
		WalshCodes[31][1] = -1614938036878540000L;
		WalshCodes[32][1] = -9223372032559810000L;
		WalshCodes[33][1] = 6148914692668170000L;
		WalshCodes[34][1] = 3689348817318890000L;
		WalshCodes[35][1] = -1844674406511960000L;
		WalshCodes[36][1] = 1085102596360830000L;
		WalshCodes[37][1] = -2712756480164650000L;
		WalshCodes[38][1] = -4882961664296370000L;
		WalshCodes[39][1] = 7595718148755990000L;
		WalshCodes[40][1] = 71777218556133100L;
		WalshCodes[41][1] = -3050531606099550000L;
		WalshCodes[42][1] = -5490956890979190000L;
		WalshCodes[43][1] = 7393053073195050000L;
		WalshCodes[44][1] = -8074936604381160000L;
		WalshCodes[45][1] = 6531726502061060000L;
		WalshCodes[46][1] = 4378410074226080000L;
		WalshCodes[47][1] = -1614987320876230000L;
		WalshCodes[48][1] = 281474976645120L;
		WalshCodes[49][1] = -3074363520626040000L;
		WalshCodes[50][1] = -5533854337126880000L;
		WalshCodes[51][1] = 7378753924479150000L;
		WalshCodes[52][1] = -8138021084010120000L;
		WalshCodes[53][1] = 6510698342184740000L;
		WalshCodes[54][1] = 4340559386448710000L;
		WalshCodes[55][1] = -1627604216802020000L;
		WalshCodes[56][1] = -9151315538050290000L;
		WalshCodes[57][1] = 6172933524171350000L;
		WalshCodes[58][1] = 3732582714024600000L;
		WalshCodes[59][1] = -1830263107610060000L;
		WalshCodes[60][1] = 1148681856222170000L;
		WalshCodes[61][1] = -2691563393544200000L;
		WalshCodes[62][1] = -4844814108379560000L;
		WalshCodes[63][1] = 7608434000728250000L;
		WalshCodes[64][1] = -9223372036854775808L;
		WalshCodes[65][1] = 6148914691236520000L;
		WalshCodes[66][1] = 3689348814741910000L;
		WalshCodes[67][1] = -1844674407370960000L;
		WalshCodes[68][1] = 1085102592571150000L;
		WalshCodes[69][1] = -2712756481427880000L;
		WalshCodes[70][1] = -4882961666570180000L;
		WalshCodes[71][1] = 7595718147998050000L;
		WalshCodes[72][1] = 71777214294589700L;
		WalshCodes[73][1] = -3050531607520060000L;
		WalshCodes[74][1] = -5490956893536110000L;
		WalshCodes[75][1] = 7393053072342740000L;
		WalshCodes[76][1] = -8074936608141340000L;
		WalshCodes[77][1] = 6531726500807660000L;
		WalshCodes[78][1] = 4378410071969970000L;
		WalshCodes[79][1] = -1614987321628270000L;
		WalshCodes[80][1] = 281470681808895L;
		WalshCodes[81][1] = -3074363522057660000L;
		WalshCodes[82][1] = -5533854339703780000L;
		WalshCodes[83][1] = 7378753923620180000L;
		WalshCodes[84][1] = -8138021087799680000L;
		WalshCodes[85][1] = 6510698340921550000L;
		WalshCodes[86][1] = 4340559384174970000L;
		WalshCodes[87][1] = -1627604217559940000L;
		WalshCodes[88][1] = -9151315542311700000L;
		WalshCodes[89][1] = 6172933522750880000L;
		WalshCodes[90][1] = 3732582711467760000L;
		WalshCodes[91][1] = -1830263108462340000L;
		WalshCodes[92][1] = 1148681852462100000L;
		WalshCodes[93][1] = -2691563394797560000L;
		WalshCodes[94][1] = -4844814110635600000L;
		WalshCodes[95][1] = 7608433999976240000L;
		WalshCodes[96][1] = 4294967295L;
		WalshCodes[97][1] = -3074457344186600000L;
		WalshCodes[98][1] = -5534023219535890000L;
		WalshCodes[99][1] = 7378697630342810000L;
		WalshCodes[100][1] = -8138269440493950000L;
		WalshCodes[101][1] = 6510615556690130000L;
		WalshCodes[102][1] = 4340410372558410000L;
		WalshCodes[103][1] = -1627653888098790000L;
		WalshCodes[104][1] = -9151594818298640000L;
		WalshCodes[105][1] = 6172840430755230000L;
		WalshCodes[106][1] = 3732415145875590000L;
		WalshCodes[107][1] = -1830318963659730000L;
		WalshCodes[108][1] = 1148435432473620000L;
		WalshCodes[109][1] = -2691645534793720000L;
		WalshCodes[110][1] = -4844961962628690000L;
		WalshCodes[111][1] = 7608384715978550000L;
		WalshCodes[112][1] = -9223090561878130000L;
		WalshCodes[113][1] = 6149008516228730000L;
		WalshCodes[114][1] = 3689517699727900000L;
		WalshCodes[115][1] = -1844618112375630000L;
		WalshCodes[116][1] = 1085350952844660000L;
		WalshCodes[117][1] = -2712673694670040000L;
		WalshCodes[118][1] = -4882812650406070000L;
		WalshCodes[119][1] = 7595767820052750000L;
		WalshCodes[120][1] = 72056498804490500L;
		WalshCodes[121][1] = -3050438512683430000L;
		WalshCodes[122][1] = -5490789322830170000L;
		WalshCodes[123][1] = 7393108929244720000L;
		WalshCodes[124][1] = -8074690180632600000L;
		WalshCodes[125][1] = 6531808643310570000L;
		WalshCodes[126][1] = 4378557928475210000L;
		WalshCodes[127][1] = -1614938036126520000L;
	}

	/**
	 * @param entrada
	 *            [2] * Realiza el cruce de la parte interna de las variables
	 *            '0' y '1' de entrada
	 */
	private void InnerCrossByte(long entrada[]) {
		long a1, b1, a2, b2;

		a1 = entrada[0];
		b1 = entrada[1];
		a2 = entrada[0];
		b2 = entrada[1];
		a1 = a1 << 32;
		a2 = a2 >>> 32;
		a2 = a2 << 32;
		b1 = b1 << 32;
		b1 = b1 >>> 32;
		b2 = b2 >>> 32;
		a2 = a2 | b2;
		b1 = b1 | a1;
		entrada[0] = a2;
		entrada[1] = b1;
	}

	/**
	 * @param entrada
	 *            [2]
	 * 
	 *            Realiza el cruce de la parte externa de las variables '0' y
	 *            '1' de entrada
	 */
	private void OutneerCrossByte(long entrada[]) {
		long a1, b1, a2, b2;

		a1 = entrada[0];
		b1 = entrada[1];
		a2 = entrada[0];
		b2 = entrada[1];
		a1 = a1 << 32;
		a1 = a1 >>> 32;
		a2 = a2 >>> 32;
		b1 = b1 << 32;
		b2 = b2 >>> 32;
		b2 = b2 << 32;
		a1 = a1 | b1;
		b2 = b2 | a2;
		entrada[0] = a1;
		entrada[1] = b2;
	}

	/**
	 * @param entrada
	 *            [2]
	 * 
	 *            Realiza el cruce de la parte mas significativa y la menos
	 *            significativa de cada una de las variables
	 */
	private void InterCrossByte(long entrada[]) {
		long a1, b1, a2, b2;

		a1 = entrada[0];
		b1 = entrada[1];
		a2 = entrada[0];
		b2 = entrada[1];
		a1 = a1 << 32;
		a2 = a2 >>> 32;
		b1 = b1 << 32;
		b2 = b2 >>> 32;
		a1 = a1 | a2;
		b1 = b1 | b2;
		entrada[0] = a1;
		entrada[1] = b1;
	}

	/**
	 * @param entrada
	 *            [2]
	 * 
	 *            Realiza el cruce de la parte mas significativa y la menos
	 *            significativa de cada una de las variables y realiza el Swap
	 *            de los bytes en la posicion 0 y 1
	 */
	private void SwapByte(long entrada[]) {
		long a1, b1, a2, b2;

		a1 = entrada[0];
		b1 = entrada[1];
		a2 = entrada[0];
		b2 = entrada[1];
		a1 = a1 << 32;
		a2 = a2 >>> 32;
		b1 = b1 << 32;
		b2 = b2 >>> 32;
		a1 = a1 | a2;
		b1 = b1 | b2;
		entrada[1] = a1;
		entrada[0] = b1;
	}

	/**
	 * @param Num
	 * @param entrada
	 *            [2] * Realiza la operacion de cruce especificada por Num entre
	 *            los valores '0' y '1' de entrada. Num puede ser: 0 para
	 *            InnerCrossByte 1 para OutneerCrossByte 2 para InterCrossByte 3
	 *            para SwapByte
	 */
	private void CrossByte(int Num, long entrada[]) {

		switch (Num) {
		case 0:
			this.InnerCrossByte(entrada);
			break;
		case 1:
			this.OutneerCrossByte(entrada);
			break;
		case 2:
			this.InterCrossByte(entrada);
			break;
		case 3:
			this.SwapByte(entrada);
			break;
		}
	}

	/**
	 * @param in
	 * @param pos
	 * @return el bit en la posicion pos
	 * 
	 *         Retorna un bit cualquiera de in entre las posiciones (del 0 al
	 *         63)
	 */
	public long GetBit(long in, int pos) {
		long SR;
		int shift;

		SR = in;
		shift = (int) (63 - pos);
		SR = SR << shift;
		SR = SR >>> 63;
		return SR;
	}

	/**
	 * @param in
	 * @param bit
	 * @param pos
	 * @return retorna 'in' con el 'bit' en la posicion 'pos' 0 &lt;= 'pos' &lt;
	 *         64
	 */
	public long SetBit(long in, long bit, int pos) {
		long salida;

		bit = bit << pos;
		salida = in | bit;
		return salida;
	}

	/**
	 * @param in
	 * @return TransposeLeft(in)
	 * 
	 *         Esta funcion convierte el entero de 64 bits en una matriz de 8x8
	 *         bits y la transpone a la Izquierda retornando el valor generado
	 *         esta operacion
	 */
	public long TransposeLeft(long in) {
		int grupo, bit;
		long SR, Temp;

		SR = 0;
		for (bit = 0; bit < 8; bit++) {
			for (grupo = 7; grupo >= 0; grupo--) {
				SR = SR << 1;
				Temp = GetBit(in, (8 * grupo + bit));
				SR = SR | Temp;
			}
		}
		return SR;
	}

	/**
	 * @param in
	 * @return TransposeRight(in)
	 * 
	 *         Esta funcion convierte el entero de 64 bits en una matriz de 8x8
	 *         bits y la transpone a la Derecha retornando el valor generado
	 *         esta operacion
	 */
	public long TransposeRight(long in) {
		int grupo, bit;
		long SR, Temp;

		SR = 0;
		for (bit = 7; bit >= 0; bit--) {
			for (grupo = 0; grupo < 8; grupo++) {
				SR = SR << 1;
				Temp = GetBit(in, (8 * grupo + bit));
				SR = SR | Temp;
			}
		}
		return SR;
	}

	/**
	 * @param in
	 * @param pos
	 * @return Retorna 8 bits de 'in' contados desde 'pos'
	 * 
	 *         NOTA: 0 &lt;= pos &lt;= 56
	 */
	public long Get8Bits(long in, int pos) {
		long SR;
		int shift;

		SR = in;
		shift = (int) (56 - pos);
		SR = SR << shift;
		SR = SR >>> 56;
		return SR;
	}

	/**
	 * @param in
	 * 
	 *            Realiza el Interleaving de las entradas in[0] e in[1]
	 */
	public void Interleaving(long in[]) {
		long[] Temporal;
		int i;

		Temporal = new long[2];
		// Realiza el cruce de las primeras filas de la matriz A
		// con las ultimas de la matriz B
		for (i = 0; i < 4; i++) {
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[0], (8 * i));
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[1], (8 * (7 - i)));
		}
		// Realiza el cruce de las ultimas filas de la matriz A
		// con las primeras de la matriz B
		for (i = 0; i < 4; i++) {
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[0], (8 * (7 - i)));
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[1], (8 * i));
		}
		// Realiza la Transposicion de los bits
		in[0] = TransposeRight(Temporal[0]);
		in[1] = TransposeLeft(Temporal[1]);
		Temporal[0] = in[0];
		Temporal[1] = in[1];
		// Realiza el cruce de las filas de la matriz A
		// con las de la matriz B
		for (i = 0; i < 4; i++) {
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[0], (8 * i));
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[1], (8 * i));
		}
		// Realiza el cruce de las filas de la matriz A
		// con las de la matriz B
		for (i = 4; i < 8; i++) {
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[0], (8 * i));
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[1], (8 * i));
		}
		// Realiza la Transposicion de los bits
		in[0] = TransposeRight(Temporal[0]);
		in[1] = TransposeLeft(Temporal[1]);
	}

	/**
	 * @param in
	 * 
	 *            Realiza el DeInterleaving de las entradas in[0] e in[1]
	 */
	public void DeInterleaving(long in[]) {
		long[] Temporal;
		int i;

		Temporal = new long[2];
		// Realiza la Transposicion de los bits
		Temporal[0] = TransposeLeft(in[0]);
		Temporal[1] = TransposeRight(in[1]);
		in[0] = Temporal[0];
		in[1] = Temporal[1];
		Temporal[0] = 0L;
		Temporal[1] = 0L;
		// Realiza el cruce de las filas de la matriz A
		// con las de la matriz B
		for (i = 0; i < 8; i += 2) {
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[1], (8 * (i + 1)));
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[1], (8 * i));
		}
		// Realiza el cruce de las filas de la matriz A
		// con las de la matriz B
		for (i = 0; i < 8; i += 2) {
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[0], (8 * (i + 1)));
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[0], (8 * i));
		}
		// Realiza la Transposicion de los bits
		in[0] = TransposeLeft(Temporal[0]);
		in[1] = TransposeRight(Temporal[1]);
		Temporal[0] = 0L;
		Temporal[1] = 0L;
		// Realiza el cruce de las primeras filas de la matriz A
		// con las ultimas de la matriz B
		for (i = 7; i >= 0; i -= 2) {
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[1], (8 * i));
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[0], (8 * (i - 1)));
		}
		// Realiza el cruce de las ultimas filas de la matriz A
		// con las primeras de la matriz B
		for (i = 0; i < 8; i += 2) {
			Temporal[0] = Temporal[0] << 8;
			Temporal[0] = Temporal[0] | Get8Bits(in[0], (8 * (i + 1)));
			Temporal[1] = Temporal[1] << 8;
			Temporal[1] = Temporal[1] | Get8Bits(in[1], (8 * i));
		}
		in[0] = Temporal[0];
		in[1] = Temporal[1];
	}

	/**
	 * Constructor por defecto, el cual cumple con la especificacion de 9
	 * bloques de codificacion y 8 de crossbytes para el interleaving definidos
	 * por el password.
	 */
	public CuaimaCrypt() {
		int j, i, NumCrossBits;

		RLorenz = null;
		RCA = new RakeCodec[9];
		j = RCA.length;
		for (i = 0; i < j; i++) {
			RCA[i] = new RakeCodec();
		}
		CrossBitsSecuen = new int[RCA.length - 1];
		NumCrossBits = CrossBitsSecuen.length;
		j = 0;
		for (i = 0; i < NumCrossBits; i++) {
			CrossBitsSecuen[i] = j;
			j++;
			if (j > 2) {
				j = 0;
			}
		}
		SeedHoppingSeq = new int[RCA[0].GetNumSC() * RCA.length];
		NumCrossBits = SeedHoppingSeq.length;
		j = 1;
		for (i = 0; i < NumCrossBits; i++) {
			SeedHoppingSeq[i] = j;
			j++;
			if (j >= NumCrossBits) {
				j = 0;
			}
		}
		InitWalshCode();
		WalshCode = 0;
	}

	/**
	 * @param NumRCA
	 * 
	 *            Constructor con definicion de numero de bloques de
	 *            codificacion el numero minimo de bloques es 2 con uno de
	 *            crossbyte definido por el password
	 */
	public CuaimaCrypt(int NumRCA) {
		int j, i, NumCrossBits;

		RLorenz = null;
		if (NumRCA < 2) {
			NumRCA = 2;
		}
		RCA = new RakeCodec[NumRCA];
		j = RCA.length;
		for (i = 0; i < j; i++) {
			RCA[i] = new RakeCodec();
		}
		CrossBitsSecuen = new int[RCA.length - 1];
		NumCrossBits = CrossBitsSecuen.length;
		j = 0;
		for (i = 0; i < NumCrossBits; i++) {
			CrossBitsSecuen[i] = j;
			j++;
			if (j > 2) {
				j = 0;
			}
		}
		SeedHoppingSeq = new int[RCA[0].GetNumSC() * RCA.length];
		NumCrossBits = SeedHoppingSeq.length;
		j = 1;
		for (i = 0; i < NumCrossBits; i++) {
			SeedHoppingSeq[i] = j;
			j++;
			if (j >= NumCrossBits) {
				j = 0;
			}
		}
		InitWalshCode();
		WalshCode = 0;
	}

	/**
	 * Resetea el sistema al estado de todas las semillas
	 */
	public void Reset() {
		int NRCA, NumRCA;

		NumRCA = this.RCA.length;
		for (NRCA = 0; NRCA < NumRCA; NRCA++) {
			RCA[NRCA].Reset();
		}
	}

	/**
	 * @return
	 * 
	 *         Retorna el Numero de Semillas que contiene el CuaimaCrypt
	 */
	public int GetNumSeeds() {
		int NumSeeds;

		NumSeeds = RCA[0].GetNumSC() * RCA.length;
		return NumSeeds;
	}

	/**
	 * @param ns
	 * @param seed
	 * 
	 *            Establece la Semanilla 'ns' al valor 'seed'
	 */
	public void SetSeed(int ns, long seed) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (ns < TotalSeeds) {
			PosRCA = (int) ns / (RCA[0].GetNumSC());
			NumSC = (int) ns - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetSeed(NumSC, seed);
		}
	}

	/**
         * Retorna el valor de la Semilla 'ns'
         * 
	 * @param ns Numero de semilla a recuperar
	 * @return  Valor de la semilla      
	 */
	public long GetSeed(int ns) {
		int TotalSeeds, PosRCA, NumSC;
		long Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (ns < TotalSeeds) {
			PosRCA = (int) ns / (RCA[0].GetNumSC());
			NumSC = (int) ns - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetSeed(NumSC);
		}
		return Salida;
	}

	/**
	 * Retorna un apuntador al ShiftCodec 'SC'
	 * 
	 * @param SC
	 * @return ShiftCodec Pointer
	 */
	public ShiftCodec GetShiftCodec(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		ShiftCodec Salida;

		Salida = null;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetShiftCodec(NumSC);
		}
		return Salida;
	}

	/**
	 * @param SC
	 * @return
	 * 
	 *         Retorna el estado del Shift Codec 'SC'
	 */
	public long GetState(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		long Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].Get_State(NumSC);
		}
		return Salida;
	}

	/**
	 * @param ns
	 * @param state
	 * 
	 *            Establece la Semanilla 'ns' al valor 'state'
	 */
	public void SetState(int ns, long state) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (ns < TotalSeeds) {
			PosRCA = (int) ns / (RCA[0].GetNumSC());
			NumSC = (int) ns - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].Set_State(NumSC, state);
		}
	}

	/**
	 * 
	 * @param SC
	 * @param postup
	 * 
	 *            Establece la posicion del crossbits hacia arriba al Shift
	 *            Codec 'SC' donde 0 &lt;= postup &lt; 32
	 */
	public void SetPostUp(int SC, int postup) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetPostUp(NumSC, postup);
		}
	}

	/**
	 * 
	 * @param SC
	 * @return Retorna la posicion de cruce de bits hacia arriba para el Shift
	 *         Codec 'SC'
	 */
	public int GetPostUp(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		int Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetPostUp(NumSC);
		}
		return Salida;
	}

	/**
	 * 
	 * @param SC
	 * @return ShiftLeap
	 * 
	 *         Retorna el valor del ShiftLeap del Shift Codec 'SC'
	 */
	public int GetShiftLeap(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		int Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetShiftLeap(NumSC);
		}
		return Salida;
	}

	/**
	 * 
	 * @param SC
	 * @param shiftleap
	 * 
	 *            Establece el valor del salto del Shift Codec 'SC' al valor
	 *            'shiftleap' donde 0 &lt; shiftleap &lt; 15
	 */
	public void SetShiftLeap(int SC, int shiftleap) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetShiftLeap(NumSC, shiftleap);
		}
	}

	/**
	 * 
	 * @param SC
	 * @param WinA
	 * 
	 *            Establece la posicion de la Ventana A del Shift Codec 'SC' al
	 *            valor 'WinA' donde 0 &lt;= shiftleap &lt; 32
	 */
	public void SetWinA(int SC, int WinA) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetWinA(NumSC, WinA);
		}
	}

	/**
	 * 
	 * @param SC
	 * @return WinA
	 * 
	 *         Retorna el valor del WinA del Shift Codec 'SC'
	 */
	public int GetWinA(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		int Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetWinA(NumSC);
		}
		return Salida;
	}

	/**
	 * 
	 * @param SC
	 * @param WinB
	 * 
	 *            Establece la posicion de la Ventana B del Shift Codec 'SC' al
	 *            valor 'WinB' donde 0 &lt;= shiftleap &lt; 32
	 */
	public void SetWinB(int SC, int WinB) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetWinB(NumSC, WinB);
		}
	}

	/**
	 * 
	 * @param SC
	 * @return WinB
	 * 
	 *         Retorna el valor del WinB del Shift Codec 'SC'
	 */
	public int GetWinB(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		int Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetWinB(NumSC);
		}
		return Salida;
	}

	/**
	 * 
	 * @param SC
	 * @param postdown
	 * 
	 *            Establece la posicion del crossbits hacia abajo al Shift Codec
	 *            'SC' donde 0 &lt;= postdown &lt; 32
	 */
	public void SetPostDown(int SC, int postdown) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetPostDown(NumSC, postdown);
		}
	}

	/**
	 * 
	 * @param SC
	 * @return Retorna la posicion de cruce de bits hacia abajo para el Shift
	 *         Codec 'SC'
	 */
	public int GetPostDown(int SC) {
		int TotalSeeds, PosRCA, NumSC;
		int Salida;

		Salida = 0;
		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			Salida = RCA[PosRCA].GetPostDown(NumSC);
		}
		return Salida;
	}

	/**
	 * @param SC
	 * @param ShCo
	 * 
	 *            Establece la Cadena de Rake Codecs hacia arriba, al unir el SC
	 */
	public void SetUpChain(int SC, ShiftCodec ShCo) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetUpChain(NumSC, ShCo);
		}
	}

	/**
	 * @param SC
	 * @param ShCo
	 * 
	 *            Establece la cadena de Rake Codecs hacia abajo, al unir los SC
	 */
	public void SetDownChain(int SC, ShiftCodec ShCo) {
		int TotalSeeds, PosRCA, NumSC;

		TotalSeeds = RCA[0].GetNumSC() * RCA.length;
		if (SC < TotalSeeds) {
			PosRCA = (int) SC / (RCA[0].GetNumSC());
			NumSC = (int) SC - (PosRCA * RCA[0].GetNumSC());
			RCA[PosRCA].SetDownChain(NumSC, ShCo);
		}
	}

	/**
	 * @return
	 * 
	 *         Retorna el numero de cruces de bits que tiene el algoritmo
	 */
	public int GetNumCrossBits() {
		return CrossBitsSecuen.length;
	}

	/**
	 * @param Pos
	 * @param CrossBit
	 * 
	 *            Establece el tipo Cossbit en la posicion Pos, con el cruce
	 *            CrossBit. El valor de 0 &lt;= 'Pos' &lt; GetNumCrossBits() El
	 *            valor de 0 &lt;= CrossBit &lt; 4
	 */
	public void SetCrossBits(int Pos, int CrossBit) {

		if (Pos < CrossBitsSecuen.length) {
			if (CrossBit < 4) {
				CrossBitsSecuen[Pos] = CrossBit;
			}
		}
	}

	/**
	 * @param Pos
	 * @return
	 * 
	 *         Retorna el tipo de CrossBit de la posicion 'Pos' Si 'Pos' es
	 *         mayor a GetNumCrossBits() retorna -1
	 */
	public int GetCrossBits(int Pos) {
		int Salida;

		Salida = -1;
		if (Pos < CrossBitsSecuen.length) {
			Salida = CrossBitsSecuen[Pos];
		}
		return Salida;
	}

	/**
	 * @param Seed
	 * @param HopTo
	 * 
	 *            Establece hacia cual semilla (HopTo) va a saltar la semilla
	 *            (Seed)
	 */
	public void SetSeedHopping(int Seed, int HopTo) {

		if ((Seed >= 0) && (Seed < SeedHoppingSeq.length)) {
			if ((HopTo >= 0) && (HopTo < SeedHoppingSeq.length)) {
				SeedHoppingSeq[Seed] = HopTo;
			}
		}
	}

	/**
	 * @param Seed
	 * @return HopTo
	 * 
	 *         Retorna hacia donde salta la semilla "seed"
	 */
	public int GetSeedHopping(int Seed) {
		int Salida;

		Salida = -1;
		if ((Seed >= 0) && (Seed < SeedHoppingSeq.length)) {
			Salida = SeedHoppingSeq[Seed];
		}
		return Salida;
	}

	/**
	 * Realiza la distribucion aleatoria de unos valores de entrada hacia unas
	 * salidas:<br>
	 * <br>
	 * 
	 * Ejemplo: <br>
	 * <br>
	 * 
	 * S[a]=b; <br>
	 * <br>
	 * 
	 * Significa que la Entrada 'a' se une con la salida 'b'.<br>
	 * <br>
	 * 
	 * @param NumValues
	 *            Numero de valores a distribuir
	 * @return Arreglo de valores distribuidos
	 */
	private int[] RandDistribuidor(int NumValues) {
		int[] Salida;
		int[] Soporte;
		int i, j, k, SopLimit;

		Salida = null;
		if (RLorenz != null) { // Verifica si se inicializo el generador de
								// numeros aleatorios de Lorenz
			if (NumValues > 0) {
				Salida = new int[NumValues];
				Soporte = new int[NumValues];
				// Llena el arreglo de soporte
				for (i = 0; i < NumValues; i++) {
					Soporte[i] = i;
				}
				// Realiza la distribucion
				SopLimit = NumValues;
				for (i = 0; i < NumValues-2; i++) {
					k = RLorenz.nextInt(SopLimit);
					Salida[i] = Soporte[k]; // Establece el salto
					for (j = k; j < SopLimit-1; j++) {
						Soporte[j]=Soporte[j+1];
					}
					SopLimit--;
				}
				Salida[i] = Soporte[1];
				Salida[i+1] = Soporte[0];
			}
		}
		return Salida;
	}

	/**
	 * 
	 * Esta funcion inicializa las semillas del cuaimacryp basado en un
	 * password, que es un String. Este password debe tener una longitud minima
	 * de 1 caracteres La funcion retorna: 0 se establecieron las semillas -1
	 * longitud del password es menor a 1 caracter -2 el passord no contiene los
	 * tipos de caracteres solicitados.
	 * 
	 * @param passw
	 *            Clave para inicializar el algoritmo
	 * @return int
	 */
	public strictfp int Password(String passw) {
		int salida;
		PasswordSparker PassSpark;
		int i, j, k, NumSeedHopping, SystemNumSeed;
		int ChainSeq[];

		// Genera el Sparker a partir del password y verifica si cumple
		PassSpark = new PasswordSparker(passw, null);
		salida = PassSpark.PasswordOK();
		if (salida == 0) {
			// Inicializa los atractores con el password
			RLorenz = new KAOSrand(PassSpark);
			// Establece las semillas de los ShiftCodec
			SystemNumSeed = this.GetNumSeeds();
			for (i = 0; i < SystemNumSeed; i++) {
				this.SetSeed(i, RLorenz.nextLong());
			}
			// Establece el tipo de los cruces de bits
			for (i = 0; i < this.GetNumCrossBits(); i++) {
				this.SetCrossBits(i, RLorenz.nextInt(4));
			}
			// Establece la secuencia de saltos de semillas
			NumSeedHopping = SeedHoppingSeq.length;
			SeedHoppingSeq=RandDistribuidor(NumSeedHopping); 
			// Establece la secuenca cruces de semillas hacia arriba
			ChainSeq = new int[SystemNumSeed];
			NumSeedHopping = ChainSeq.length;
			ChainSeq=RandDistribuidor(NumSeedHopping);
			for(j=0;j<NumSeedHopping;j++){
				this.SetUpChain(j, this.GetShiftCodec(ChainSeq[j]));
			}
			// Establece el cruce de semillas hacia abajo
			ChainSeq=RandDistribuidor(NumSeedHopping);
			for(j=0;j<NumSeedHopping;j++){
				this.SetDownChain(j, this.GetShiftCodec(ChainSeq[j]));
			}
			// Establece los puntos de inicio de las ventanas de 32 bits en el
			// cruce del UpChain
			for (j = 0; j < SystemNumSeed; j++) {
				k = RLorenz.nextInt(32);
				this.SetPostUp(j, k);
			}
			// Establece los puntos de inicio de las ventanas de 32 bits en el
			// cruce del DownChain
			for (j = 0; j < SystemNumSeed; j++) {
				k = RLorenz.nextInt(32);
				this.SetPostDown(j, k);
			}
			// Establece los puntos de inicio de la Ventana A de 32 bits de los
			// Shift Codec
			for (j = 0; j < SystemNumSeed; j++) {
				k = RLorenz.nextInt(32);
				this.SetWinA(j, k);
			}
			// Establece los puntos de inicio de la Ventana B de 32 bits de los
			// Shift Codec
			for (j = 0; j < SystemNumSeed; j++) {
				k = RLorenz.nextInt(32);
				this.SetWinB(j, k);
			}
			// Establece el valor de Corrimiento para cada ShiftCodec hasta un
			// maximo de 15 bits
			for (j = 0; j < SystemNumSeed; j++) {
				k = RLorenz.nextInt(15);
				this.SetShiftLeap(j, k);
			}
			// Calcula el codigo Walsh a utilizar para el spread de los bits
			WalshCode = RLorenz.nextInt(WalshCodes.length);
			if (WalshCode == 0) {
				WalshCode = 1;
			}
		}
		return salida;
	}

	/**
	 * @param entrada
	 * 
	 *            Codifica las dos palabras '0' y '1' pasadas por referencia en
	 *            entrada[2]
	 */
	public void Codec(long entrada[]) {
		int i, NumRCA;

		NumRCA = RCA.length;
		// Realiza la ortogonalizacion de los bits usando el codigo Walsh
		entrada[0] = entrada[0] ^ WalshCodes[WalshCode][0];
		entrada[1] = entrada[1] ^ WalshCodes[WalshCode][1];
		// Realiza el Interleaving de los bits de entrada
		Interleaving(entrada);
		// Codifica las entradas y realiza el cruce de bits
		for (i = 0; i < NumRCA - 1; i++) {
			RCA[i].Codec(entrada);
			CrossByte(CrossBitsSecuen[i], entrada);
		}
		// Realiza la ultima codificacion
		RCA[i].Codec(entrada);
		// Realiza el corrimiento de las semillas
		for (i = 0; i < NumRCA; i++) {
			RCA[i].ShiftCodec();
		}
		// Realiza el salto de las semillas
		SeedHop();
	}

	/**
	 * @param entrada
	 * 
	 *            Decodifica las dos palabras '0' y '1' pasadas por referencia
	 *            en entrada[2]
	 */
	public void Decodec(long entrada[]) {
		int i, NumRCA;

		NumRCA = RCA.length;
		// Realiza la Decodificacion de los datos de entrada
		for (i = NumRCA - 1; i > 0; i--) {
			RCA[i].Decodec(entrada);
			CrossByte(CrossBitsSecuen[i - 1], entrada);
		}
		RCA[0].Decodec(entrada);
		// Realiza el DeInterleaving de los bits de Salida
		DeInterleaving(entrada);
		// Realiza el deortogonalizacion de los bits usando el codigo Walsh
		entrada[0] = entrada[0] ^ WalshCodes[WalshCode][0];
		entrada[1] = entrada[1] ^ WalshCodes[WalshCode][1];
		// Realiza el corrimiento de las semillas
		for (i = 0; i < NumRCA; i++) {
			RCA[i].ShiftDecodec();
		}
		// Realiza el salto de las semillas
		SeedHop();
	}

	/**
	 * Realiza el Salto de las Distintas Semillas Acorde con la Secuencia
	 * especificada
	 */
	private void SeedHop() {
		int i, NumSeed;
		long Semilla;

		NumSeed = SeedHoppingSeq.length;
		for (i = 0; i < NumSeed; i++) {
			// Verifica que sea un salto valido
			if ((SeedHoppingSeq[i] >= 0) && (SeedHoppingSeq[i] < NumSeed)) {
				// Realiza el swap de las dos semillas
				Semilla = GetState(SeedHoppingSeq[i]);
				SetState(SeedHoppingSeq[i], GetState(i));
				SetState(i, Semilla);
			}
		}
	}

}
