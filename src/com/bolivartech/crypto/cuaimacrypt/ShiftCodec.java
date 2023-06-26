package com.bolivartech.crypto.cuaimacrypt;

import com.bolivartech.utils.random.MersenneTwisterPlus;

/**
 * Copyright 2007,2009,2010 BolivarTech C.A.
 *
 * This Class is part of CuaimaCrypt.
 *
 * @author Julian Bolivar
 * @version 2.1.0
 *
 * <p>
 * Change Log:
 * </p>
 * <ul>
 * <li>v2.1.0 - Finalize method was improved to be safer.</li>
 * <li>v2.0.0 - The Random generator is initializated using the new class
 * MersenneTwisterPlus that was implemente by BolivarTech.</li>
 * </ul>
 */
public class ShiftCodec {

    private long seed, shift_register;
    private int posup, posdown, ShiftLeap, win_a, win_b, entrada, salida;
    private ShiftCodec upchain, downchain;
    private MersenneTwisterPlus rnd;

    /**
     * Default Constructor
     *
     * The seed is initially with a random number
     */
    ShiftCodec() {

        rnd = new MersenneTwisterPlus();
        seed = rnd.nextLong();
        shift_register = seed;
        upchain = null;
        downchain = null;
        posup = 5;
        posdown = 15;
        ShiftLeap = 1;
        win_a = 9;
        win_b = 27;
        entrada = 0;
        salida = 0;
    }

    /**
     * @param semilla
     *
     * Constructor with initial seed value
     */
    ShiftCodec(long semilla) {

        seed = semilla;
        shift_register = seed;
        upchain = null;
        downchain = null;
        posup = 5;
        posdown = 15;
        ShiftLeap = 1;
        win_a = 9;
        win_b = 27;
        entrada = 0;
        salida = 0;
    }

    /**
     * @param semilla
     * @param up
     * @param down
     *
     * Constructor with initial seed value and make the chain to others
     * ShiftCodecs
     */
    ShiftCodec(long semilla, ShiftCodec up, ShiftCodec down) {

        seed = semilla;
        shift_register = seed;
        upchain = up;
        downchain = down;
        posup = 5;
        posdown = 15;
        ShiftLeap = 1;
        win_a = 9;
        win_b = 27;
        entrada = 0;
        salida = 0;
    }

    /*
     *
     * 
     * @see java.lang.Object#finalize()
     * 
     * Clear the seed and the shiftcodec state for security
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            seed = rnd.nextLong();
            shift_register = rnd.nextLong();
            posup = rnd.nextInt();
            posdown = rnd.nextInt();
            ShiftLeap = rnd.nextInt();
            win_a = rnd.nextInt();
            win_b = rnd.nextInt();
            entrada = rnd.nextInt();
            salida = rnd.nextInt();
        } catch (Throwable t) {
            throw t;
        } finally {
            super.finalize();
        }
    }

    /**
     * @return
     *
     * Get the ShiftCodec Seed
     */
    public long getSeed() {
        return seed;
    }

    /**
     * @param seed
     *
     * Set the ShiftCodec Seed
     */
    public void setSeed(long seed) {
        this.seed = seed;
        shift_register = this.seed;
    }

    /**
     * @return
     *
     * Return the ShiftCodec state
     */
    public long getShiftCodec_state() {
        return shift_register;
    }

    /**
     * @param state
     *
     * Set the ShiftCodec State
     */
    public void setShiftCodec_state(long state) {
        shift_register = state;
    }

    /**
     * Reset the ShiftCodec to the seed state
     */
    public void Reset() {
        shift_register = seed;
    }

    /**
     * Generate a new random seed
     */
    public void RamdomSeed() {

        //MersenneTwister rnd = new MersenneTwister();
        seed = rnd.nextLong();
        shift_register = seed;
    }

    /**
     *
     * @param up
     *
     * Make the Chain connection to other ShiftCodec in Up fordwar
     */
    public void UpChain(ShiftCodec up) {
        upchain = up;
    }

    /**
     *
     * @param down
     *
     * Make the Chain connection to other ShiftCodec in Down fordwar
     */
    public void DownChain(ShiftCodec down) {
        downchain = down;
    }

    /**
     *
     * @param up
     * @param down
     *
     * Make the Chain connection to others ShiftCodecs in both directions
     */
    public void Chain(ShiftCodec up, ShiftCodec down) {
        upchain = up;
        downchain = down;
    }

    /**
     * @param pos
     * @return
     *
     * Retorna una ventana de 32 bits cualquiera del Shift Register (empezando
     * del 0 al 31)
     */
    public int GetBits(int pos) {
        long SR;
        int Salida;

        if ((pos < 32) && (pos >= 0)) {
            SR = shift_register;
            SR = SR >>> pos;
            Salida = (int) SR;
        } else {
            Salida = -1;
        }
        return Salida;
    }

    /**
     * Realiza el desplazamiento del registro en 'ShiftLeap' bits e inserta los
     * 32 bit calculados a partir de la entrada y de las cadenas en la cola del
     * shift register para el proceso de codificacion.
     */
    public void ShiftCdec() {
        long SR;
        int a, b;

		// codigo para hacer la cadena de bits
        // en la version anterior se verificaba si la cadena existia
        // pero por performance se presupone que la cadena existe
        // y no se verifican punteros nulos para aumentar la 
        // velocidad del proceso de codificacion
        a = this.GetBits(win_a) ^ upchain.GetBits(posup);
        b = this.GetBits(win_b) ^ downchain.GetBits(posdown);
        a = a ^ b;
        b = a ^ entrada;
        SR = (long) b;
        SR = SR << 31;
        shift_register = shift_register >>> ShiftLeap;
        shift_register = SR ^ shift_register;
    }

    /**
     * Realiza el desplazamiento del registro en 'ShiftLeap' bits e inserta los
     * 32 bit calculados a partir de la entrada y de las cadenas en la cola del
     * shift register para el proceso de decodificacion.
     */
    public void ShiftDCdec() {
        long SR;
        int a, b;

        // codigo para hacer la cadena de bits
        // en la version anterior se verificaba si la cadena existia
        // pero por performance se presupone que la cadena existe
        // y no se verifican punteros nulos para aumentar la 
        // velocidad del proceso de codificacion
        a = this.GetBits(win_a) ^ upchain.GetBits(posup);
        b = this.GetBits(win_b) ^ downchain.GetBits(posdown);
        a = a ^ b;
        b = a ^ salida;
        SR = (long) b;
        SR = SR << 31;
        shift_register = shift_register >>> ShiftLeap;
        shift_register = SR ^ shift_register;
    }

    /**
     * @param in
     * @return
     *
     * Realiza la codificacion del bit pasado como parametro in retornando el
     * valor codificado en la salida
     */
    public int BitsCodec(int in) {

        entrada = in;
        salida = (int) shift_register;
        salida = entrada ^ salida;
        return salida;
    }

    /**
     * @param in
     * @return
     *
     * Realiza la decodificacion del bit pasado como parametro en in retornando
     * el valor decodificado en la salida
     */
    public int BitsDecodec(int in) {

        entrada = in;
        salida = (int) shift_register;
        salida = entrada ^ salida;
        return salida;
    }

    /**
     * @return la posicion desde donde toma los bits en el upchain
     */
    public int getPosUp() {
        return posup;
    }

    /**
     * @param posup
     *
     * Establece desde donde se toman los bits para el upchain 0 &lt;= posup &lt;32
     */
    public void setPosUp(int posup) {
        if ((posup < 32) && (posup >= 0)) {
            this.posup = posup;
        } else {
            this.posup = 29;
        }
    }

    /**
     * @return la posicion desde donde se toman los bits para el downchain
     */
    public int getPosDown() {
        return posdown;
    }

    /**
     * @param posdown
     *
     * Establece desde donde se toman los bits para el downchain 0 &lt;= posdown &lt; 32
     */
    public void setPosDown(int posdown) {
        if ((posdown < 32) && (posdown >= 0)) {
            this.posdown = posdown;
        } else {
            this.posdown = 9;
        }
    }

    /**
     * @return el salto del shift register 'ShiftLeap'
     */
    public int getShiftLeap() {
        return ShiftLeap;
    }

    /**
     * @param shiftPeap
     *
     * Establece el valor del salto del Shift Register
     */
    public void setShiftLeap(int shiftPeap) {
        if ((shiftPeap > 0) && (shiftPeap < 15)) {
            ShiftLeap = shiftPeap;
        } else {
            ShiftLeap = 7;
        }
    }

    /**
     * @return the win_a
     *
     * win_a es el punto de inicio de la ventana de cruce A del SC
     */
    public int getWinA() {
        return win_a;
    }

    /**
     * @param win_A
     *
     * win_a es el punto de inicio de la ventana de cruce A del SC
     */
    public void setWinA(int win_A) {
        if ((win_A < 32) && (win_A >= 0)) {
            this.win_a = win_A;
        }

    }

    /**
     * @return the win_b
     *
     * win_b es el punto de inicio de la ventana de cruce B del SC
     */
    public int getWinB() {
        return win_b;
    }

    /**
     * @param win_B
     *
     * win_b es el punto de inicio de la ventana de cruce B del SC
     */
    public void setWinB(int win_B) {
        if ((win_B < 32) && (win_B >= 0)) {
            this.win_b = win_B;
        }
    }

    /**
     * @return La entrada almacenada en el ShiftCodec
     */
    public int getEntrada() {
        return entrada;
    }

    /**
     * @return la salida almacenada en el ShiftCodec
     */
    public int getSalida() {
        return salida;
    }

    /**
     * Realiza la verificacion de que el UpChain no sea NULL
     *
     * @return TRUE si la cadena no es nula y FALSE si la cadena es nula
     */
    public boolean CheckUpChain() {
        boolean Salida;

        Salida = true;
        if (upchain == null) {
            Salida = false;
        }
        return Salida;
    }

    /**
     * Realiza la verificacion de que el DownUpChain no sea NULL
     *
     * @return TRUE si la cadena no es nula y FALSE si la cadena es nula
     */
    public boolean CheckDownChain() {
        boolean Salida;

        Salida = true;
        if (downchain == null) {
            Salida = false;
        }
        return Salida;
    }

    /**
     * Realiza la verificacion de la cadena en ambos sentidos
     *
     * @return TRUE si ambas cadenas no son nulas y FALSE si alguna de las
     * cadenas es nula
     */
    public boolean CheckChain() {
        boolean Salida;

        Salida = true;
        if ((downchain == null) || (upchain == null)) {
            Salida = false;
        }
        return Salida;
    }

}
