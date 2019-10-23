/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssi1;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
public class Albergue {

    String nombre;
    String fecha;
    String lugar;
    String incidencias;

    public Albergue(String nombre, String fecha, String lugar, String incidencias) {

        this.nombre = nombre;
        this.incidencias = incidencias;
        this.fecha = fecha;
        this.lugar = lugar;
        
    }

    private byte[] crearDatosAlbergue() {
        String datos = "{nombre:" + this.nombre + ", fecha:+" + this.fecha + ", lugar:" + this.lugar + ", incidencias:" + this.incidencias;
        return datos.getBytes();
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    public Paquete sellarCredencial(PublicKey publicaOficina, PrivateKey privadaAlbergue, Paquete p) throws NoSuchAlgorithmException, IOException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        
        byte[] datosAlbergue = crearDatosAlbergue();   
        SecretKey claveSecreta = crearClaveSecreta();
        byte [] resumenDatos = resumirDatos(datosAlbergue);
        resumenDatos=cifrarAsimetricoKR (resumenDatos,privadaAlbergue);
        
        byte[] datosCifrados = cifrarDatos(datosAlbergue, claveSecreta);
        byte[] claveCifrada = cifrarClaveSecreta(claveSecreta, publicaOficina);
        
       Paquete toret = p;
       
       StringBuilder identif = new StringBuilder();
       identif.append(nombre);
       identif.append("_datos");
       StringBuilder identif2 = new StringBuilder();
       identif.append(nombre);
       identif.append("_claveCifrada");
       StringBuilder identif3 = new StringBuilder();
       identif.append(nombre);
       identif.append("_resumen");
        
        toret.anadirBloque(identif.toString(), datosCifrados);
        toret.anadirBloque(identif2.toString(), claveCifrada);
        toret.anadirBloque(identif3.toString(), resumenDatos);
        
        return toret;
        
        
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

        byte[] bufferCifrado = cifrador.doFinal(datos);
        System.out.println("TEXTO CIFRADO CON DES");
        System.out.write(bufferCifrado, 0, bufferCifrado.length);
        return bufferCifrado;

    }

    private byte[] cifrarClaveSecreta(SecretKey clavesecreta, PublicKey publicaOficina) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        byte[] claveArray = clavesecreta.getEncoded();
        cifrador.init(Cipher.ENCRYPT_MODE, publicaOficina);
        System.out.println("3a. Cifrar con clave publica");
        byte[] bufferCifrado = cifrador.doFinal(claveArray);
        System.out.println("TEXTO CIFRADO");
        return bufferCifrado;

    }

    private byte[] resumirDatos(byte[] datos) throws NoSuchAlgorithmException, IOException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        messageDigest.update(datos); // Pasa texto de entrada a la funciÃ³n resumen

        byte[] resumen = messageDigest.digest(); // Completar el resumen
        return resumen;

    }
    
    
    private byte[] cifrarAsimetricoKR(byte[] datos, PrivateKey clave) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       
       Cipher cifrador = Cipher.getInstance("RSA", "BC");    
        System.out.println("4a. Cifrar con clave privada");
        cifrador.init(Cipher.ENCRYPT_MODE, clave);
      byte [] bufferCifrado = cifrador.doFinal(datos);
      System.out.println("TEXTO CIFRADO");
       return bufferCifrado;
   }

}
