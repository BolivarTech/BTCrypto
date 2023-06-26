package com.bolivartech.crypto.cuaimacrypt;

/**
 * Copyright 2007,2009,2010 BolivarTech C.A.
 * 
 *   This Class is part of CuaimaCrypt.
 * 
 * @author Julian Bolivar
 * @version 2.0.0
 *
 * <p>
 * Change Log:
 * </p>
 * <ul>
 *  <li>v2.0.0 - The Random generator is initializated using the new class MersenneTwisterPlus that was implemente by BolivarTech.</li>
 * </ul>
 */
public class RakeCodec {

	private ShiftCodec rake[];

	/**
	 * 
	 * Constructor por defecto, genera un RakeCodec de 64 bits todos encadenados
	 * formando el anillo de ShiftCodecs
	 */
	RakeCodec() {
		int i, raketeeths;

		rake = new ShiftCodec[4];
		raketeeths = rake.length;
		for (i = 0; i < raketeeths; i++) {
			rake[i] = new ShiftCodec();
		}
		for (i = 0; i < raketeeths; i++) {
			if (i < raketeeths - 1) {
				rake[i].UpChain(rake[i + 1]);
			} else {
				rake[i].UpChain(rake[0]);
			}
			if (i > 0) {
				rake[i].DownChain(rake[i - 1]);
			} else {
				rake[i].DownChain(rake[raketeeths - 1]);
			}
		}
	}

	/**
	 * @param SC
	 * @param seed
	 * 
	 * Establece la semilla 'seed' al Shift Codec 'SC'
	 */
	public void SetSeed(int SC, long seed) {

		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setSeed(seed);
		}
	}

	/**
	 * @param SC
	 * @return
	 * 
	 * Retorna la semilla del Shift Codec 'SC' si el Shift Codec 'SC' no existe
	 * retorna 0
	 */
	public long GetSeed(int SC) {
		long Salida;

		Salida = 0;
		if ((SC < rake.length) && (SC >= 0)) {
			Salida = rake[SC].getSeed();
		}
		return Salida;
	}

	/**
	 * @return
	 * 
	 * retorne el numero de dientes del Rake Codec
	 */
	public int GetRakeTeeths() {

		return rake.length;
	}

	/**
	 * @param SC
	 * 
	 * Establece el numero de dientes del Rake Codec, hasta un maximo de 64
	 * dientes, los nuevos dientes son inicializados con semillas aleatorias
	 */
	public void SetRakeTeeths(int SC) {
		int i, raketeeths;
		ShiftCodec temprake[];

		if ((SC > 0) && (SC < 65)) {
			temprake = new ShiftCodec[SC];
			raketeeths = temprake.length;
			for (i = 0; i < raketeeths; i++) {
				temprake[i] = rake[i];
			}
			rake = temprake;
			for (i = 0; i < raketeeths; i++) {
				if (i < raketeeths - 1) {
					rake[i].UpChain(rake[i + 1]);
				} else {
					rake[i].UpChain(rake[0]);
				}
				if (i > 0) {
					rake[i].DownChain(rake[i - 1]);
				} else {
					rake[i].DownChain(rake[raketeeths - 1]);
				}
			}
		}
	}

	/**
	 * @param SC
	 * @param ShCo
	 * 
	 * Establece la Cadena de Rake Codecs hacia arriba, al unir los extremos de
	 * los dos Racke
	 */
	public void SetUpChain(int SC,ShiftCodec ShCo) {

		if ((SC >= 0) && (SC < rake.length)) {
			rake[SC].UpChain(ShCo);
		}
	}

	/**
	 * @param SC
	 * @param ShCo
	 * 
	 * Establece la cadena de Rake Codecs hacia abajo, al unir los extremos de
	 * los dos Rakes
	 */
	public void SetDownChain(int SC,ShiftCodec ShCo) {

		if ((SC >= 0) && (SC < rake.length)) {
			rake[SC].DownChain(ShCo);
		}
	}

	/**
	 * Reinicia el Rake Codec a sus semillas
	 */
	public void Reset() {
		int raketeeths, i;

		raketeeths = rake.length;
		for (i = 0; i < raketeeths; i++) {
			rake[i].Reset();
		}
	}

	/**
	 * @param SC
	 * @return
	 * 
	 * Retorna el estado del Shift Cocec 'SC'
	 */
	public long Get_State(int SC) {
		long Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getShiftCodec_state();
		}
		return Salida;
	}
	
	/**
	 * @param SC
	 * @param state
	 * 
	 * Establece la estado del Shift Codec 'SC' al valor de 'state'
	 */
	public void Set_State(int SC, long state) {

		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setShiftCodec_state(state);
		}
	}
	
	/**
	 * 
	 * @param SC
	 * @param postup
	 * 
	 * Establece la posicion del crossbits hacia arriba al Shift Codec 'SC' donde 0 &le; postup &lt; 32 
	 */
	public void SetPostUp(int SC, int postup){
		
		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setPosUp(postup);
		}
	}
	
	/**
	 * 
	 * @param SC
	 * @return Retorna la posicion de cruce de bits hacia arriba para el Shift Codec 'SC'
	 */
	public int GetPostUp(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getPosUp();
		}
		return Salida;		
	}
	
	/**
	 * 
	 * @param SC
	 * @return ShiftLeap
	 * 
	 *  Retorna el valor del ShiftLeap del Shift Codec 'SC'
	 */
	public int GetShiftLeap(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getShiftLeap();
		}
		return Salida;		
		
	}
	
	/**
	 * 
	 * @param SC
	 * @param shiftleap
	 * 
	 *  Establece el valor del salto del Shift Codec 'SC' al valor 'shiftleap' donde 0 &lt; shiftleap &lt; 15 
	 */
	public void SetShiftLeap(int SC, int shiftleap){

		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setShiftLeap(shiftleap);
		}
	}
	
	/**
	 * 
	 * @param SC
	 * @param postdown
	 * 
	 * Establece la posicion del crossbits hacia abajo al Shift Codec 'SC' donde 0 &le; postdown &lt; 32
	 */
	public void SetPostDown(int SC, int postdown){
		
		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setPosDown(postdown);
		}
	}
	
	/**
	 * 
	 * @param SC
	 * @return Retorna la posicion de cruce de bits hacia abajo para el Shift Codec 'SC'
	 */
	public int GetPostDown(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getPosDown();
		}
		return Salida;
	}

	/**
	 * 
	 * @param SC
	 * @param WinA
	 * 
	 * Establece la posicion del crossbits de la ventana A del Shift Codec 'SC' donde 0 &le; WinA &lt; 32
	 */
	public void SetWinA(int SC, int WinA){
		
		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setWinA(WinA);
		}
	}
	
	/**
	 * 
	 * @param SC
	 * @return Retorna la posicion de la ventana A para el Shift Codec 'SC'
	 */
	public int GetWinA(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getWinA();
		}
		return Salida;
	}	
	
	/**
	 * 
	 * @param SC
	 * @param WinB
	 * 
	 * Establece la posicion del crossbits de la ventana B del Shift Codec 'SC' donde 0 &le; WinB &lt; 32
	 */
	public void SetWinB(int SC, int WinB){
		
		if ((SC < rake.length) && (SC >= 0)) {
			rake[SC].setWinB(WinB);
		}
	}
	
	/**
	 * 
	 * @param SC
	 * @return Retorna la posicion de la ventana B para el Shift Codec 'SC'
	 */
	public int GetWinB(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getWinB();
		}
		return Salida;
	}	
	
	/**
	 * @param entrada
	 * @return -1 si no cumple el numero de entradas con el numero de teeths
	 *         0 codifico todo ok
	 * 
	 * Realiza la codificacion de las entradas de 64 bits
	 * las entradas deben ser la mitad de rake teeths
	 * 
	 * Por velocidad se presuponen una entrada de 2 elementos
	 * y 4 rakecodec
	 */
	public int Codec(long entrada[]) {
		long salida, BitSal;
		int BitEnt, i,j, raketeeths,numentradas;

		// en la version original se tomaban estos valores 
		// de la longitud del arreglo
		// por velocidad del codigo se dejaron fijos 
/*		raketeeths = rake.length;
		numentradas = entrada.length; */
		raketeeths = 2;  // para evitar tener que dividir entre 2 en for for (i = 0; i < raketeeths/2; i++) 
		numentradas = 2;
		// en la version original se verifica que
		// raketeeths == 2*numentradas
		// en esta por velocidad se presupone que esta condicion
		// se cumple
//		if(raketeeths == 2*numentradas){
			for (j = 0; j < numentradas; j++) {
			   salida = 0;
			   for (i = 0; i < raketeeths; i++) {
				   BitEnt = (int)(entrada[j] >>> i*32);
				   BitSal = (int)(rake[(raketeeths*j)+i].BitsCodec(BitEnt));
				   BitSal = BitSal << i*32;
				   salida = salida << i*32;
				   salida = salida >>> i*32;
				   salida = salida | BitSal;
			   }
			   entrada[j] = salida; 
			}
//		}
//		else return -1;
		return 0;
	}

	/**
	 * @param entrada
	 * @return -1 si no cumple el numero de entradas con el numero de teeths
	 *         0 codifico todo ok
	 * 
	 * Realiza la decodificacion de los 64 bits de la entrada
	 * 
	 * Por velocidad se presuponen una entrada de 2 elementos
	 * y 4 rakecodec
	 */
	public int Decodec(long entrada[]) {
		long salida, BitSal;
		int BitEnt, i,j, raketeeths,numentradas;

		// en la version original se tomaban estos valores 
		// de la longitud del arreglo
		// por velocidad del codigo se dejaron fijos 
/*		raketeeths = rake.length;
		numentradas = entrada.length; */
		raketeeths = 2;  // para evitar tener que dividir entre 2 en for for (i = 0; i < raketeeths/2; i++) 
		numentradas = 2;
		// en la version original se verifica que
		// raketeeths == 2*numentradas
		// en esta por velocidad se presupone que esta condicion
		// se cumple
//		if(raketeeths == 2*numentradas){
			for (j = 0; j < numentradas; j++) {
			   salida = 0;
			   for (i = 0; i < raketeeths; i++) {
				   BitEnt = (int)(entrada[j] >>> i*32);
				   BitSal = rake[(raketeeths*j)+i].BitsDecodec(BitEnt);
				   BitSal = BitSal << i*32;
				   salida = salida << i*32;
				   salida = salida >>> i*32;
				   salida |= BitSal;
			   }
			   entrada[j] = salida; 
			}
//		}
//		else return -1;
		return 0;
	}

	/**
	 *  Realiza el shift de todos las semillas en el rake para el proceso de Codificacion
	 *
	 */
	public void ShiftCodec(){
		int i,raketeeths;
		
		//raketeeths=rake.length;
		raketeeths = 4;
		for(i=0;i<raketeeths;i++){
			rake[i].ShiftCdec();
		}
	}
	
	/**
	 *  Realiza el shift de todos las semillas en el rake para el proceso de Decodificacion
	 *
	 */
	public void ShiftDecodec(){
        int i,raketeeths;
		
		//raketeeths=rake.length;
		raketeeths = 4;
		for(i=0;i<raketeeths;i++){
			rake[i].ShiftDCdec();
		}
	}
	/**
	 * 
	 * @param SC
	 * @return Retorna el valor almacenado como entrada en el Shift Codec 'SC'
	 */
	public int GetEntrada(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getEntrada();
		}
		return Salida;
	}	

	/**
	 * 
	 * @param SC
	 * @return Retorna el valor almacenado como salida en el Shift Codec 'SC'
	 */
	public int GetSalida(int SC){
		int Salida;

		Salida = 0;
		if ((SC >= 0) && (SC < rake.length)) {
			Salida = rake[SC].getSalida();
		}
		return Salida;
	}	

	/**
	 * Retorna el Numero de Shift Codec contenidos en el RakeCodec
	 * 
	 * @return Numero de Shift Codec
	 */
	public int GetNumSC(){
	   
		return rake.length;
	}
	
	/**
	 *  Verifica si todas las cadenas de subida del rake codec estan bien
	 *  
	 *  @return TRUE si todas las cadenas no son nulas y FALSE si almenos una cadena es nula
	 */
	public boolean CheckUpChain(){
		boolean Salida;
		int i;
		
		Salida = true;
		for(i=0;((i<rake.length) && Salida);i++){
			if(!rake[i].CheckUpChain()){
				Salida = false;
			}
		}
		return Salida;
	}
	
	/**
	 *  Verifica si todas las cadenas de bajada del rake codec estan bien
	 *  
	 *  @return TRUE si todas las cadenas no son nulas y FALSE si almenos una cadena es nula
	 */
	public boolean CheckDownChain(){
		boolean Salida;
		int i;
		
		Salida = true;
		for(i=0;((i<rake.length) && Salida);i++){
			if(!rake[i].CheckDownChain()){
				Salida = false;
			}
		}
		return Salida;
	}
	
	/**
	 *  Verifica si todas las cadenas del rake codec estan bien
	 *  
	 *  @return TRUE si todas las cadenas no son nulas y FALSE si almenos una cadena es nula
	 */
	public boolean CheckChain(){
		boolean Salida;
		int i;
		
		Salida = true;
		for(i=0;((i<rake.length) && Salida);i++){
			if(!rake[i].CheckChain()){
				Salida = false;
			}
		}
		return Salida;
	}

	/**
	 * Retorna un apuntador al ShiftCodec 'SC'
	 * 
	 * @param SC
	 * @return ShiftCodec Pointer
	 */
	public ShiftCodec GetShiftCodec(int SC){
		
		if((SC>=0)&&(SC<rake.length)){
		    return rake[SC];	
		}
		return null;	
	}
}
