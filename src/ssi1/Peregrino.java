/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssi1;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author danid
 */
public class Peregrino {

    String nombre;
    String motivo;
    String dni;
    String domicilio;
    String fecha;
    String lugar;

    public Peregrino(String nombre, String dni, String motivo, String domicilio, String fecha, String lugar) {

        this.nombre = nombre;
        this.dni = dni;
        this.motivo = motivo;
        this.domicilio = domicilio;
        this.fecha = fecha;
        this.lugar = lugar;

    }

    public Paquete crearCredencial(PublicKey publicaOficina, PrivateKey privadaPeregrino) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchProviderException, IOException {

        byte[] datosPeregrino = crearDatosPeregrino();
        SecretKey claveSecreta = crearClaveSecreta();
        System.out.println("Clave secreta : --------");
        System.out.println(new String(claveSecreta.getEncoded()));
        System.out.println("--------");
        byte[] resumenDatos = resumirDatos(datosPeregrino);
        resumenDatos = cifrarAsimetricoKR(resumenDatos, privadaPeregrino);

        byte[] datosCifrados = cifrarDatos(datosPeregrino, claveSecreta);
        byte[] claveCifrada = cifrarClaveSecreta(claveSecreta, publicaOficina);

        Paquete toret = new Paquete();

        toret.anadirBloque("datosPeregrino", datosCifrados);
        toret.anadirBloque("claveCifradaPeregrino", claveCifrada);
        toret.anadirBloque("resumenPeregrino", resumenDatos);       //comprobar llamadas--------------------------------

        return toret;

    }

    private byte[] crearDatosPeregrino() {
        String datos = "{nombre:" + this.nombre + ", dni:" + this.dni + ", motivo:" + this.motivo + ", domiclio:" + this.domicilio
                + " fecha:" + this.fecha + " lugar:" + this.lugar;

        return datos.getBytes();

    }

    public SecretKey crearClaveSecreta() throws NoSuchAlgorithmException {

        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56); // clave de 56 bits
        SecretKey clave = generadorDES.generateKey();

        return clave;
    }

    private byte[] cifrarDatos(byte[] datos, SecretKey clave) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");

        cifrador.init(Cipher.ENCRYPT_MODE, clave);
        System.out.println(new String(datos));
        System.out.println("4a. Cifrar con clave secreta");
        byte[] bufferCifrado = cifrador.doFinal(datos);
        System.out.println("DATOS CIFRADOS");
        System.out.write(bufferCifrado, 0, bufferCifrado.length);
        return bufferCifrado;

    }

    private byte[] cifrarClaveSecreta(SecretKey clavesecreta, PublicKey publicaOficina) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        byte[] claveArray = clavesecreta.getEncoded();
        cifrador.init(Cipher.ENCRYPT_MODE, publicaOficina);
        System.out.println("3a. Cifrar con clave publica");
        byte[] bufferCifrado = cifrador.doFinal(claveArray);
        System.out.println(new String(bufferCifrado));
        System.out.println("CLAVE CIFRADA");
        return bufferCifrado;

    }

    private byte[] resumirDatos(byte[] datos) throws NoSuchAlgorithmException, IOException {
        System.out.println("RESUMIR DATOS");
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        messageDigest.update(datos); // Pasa texto de entrada a la funciÃ³n resumen

        byte[] resumen = messageDigest.digest(); // Completar el resumen
        return resumen;

    }

    private byte[] cifrarAsimetricoKR(byte[] datos, PrivateKey clave) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        System.out.println("4a. Cifrar con clave privada");
        System.out.println(new String(datos));
        cifrador.init(Cipher.ENCRYPT_MODE, clave);
        byte[] bufferCifrado = cifrador.doFinal(datos);
        System.out.println(new String(bufferCifrado));
        System.out.println("TEXTO CIFRADO");
        return bufferCifrado;
    }

}
