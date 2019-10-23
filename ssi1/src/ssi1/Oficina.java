/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssi1;

import java.io.FileInputStream;
import java.io.IOException;
import static java.lang.Byte.compare;
import static java.lang.System.in;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author danid
 */
public class Oficina {

    String nombre;

    public Oficina(String nombre) {
        this.nombre = nombre;
    }

    public byte[] descifrarDatosSimetrico(SecretKey clave, byte[] b) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifrador.init(Cipher.DECRYPT_MODE, clave);

        byte[] bufferPlano;

        byte[] bytesLeidos = b;
        bufferPlano = cifrador.update(bytesLeidos); // Pasa texto claro leido al cifrador

        bufferPlano = cifrador.doFinal(); // Completar descifrado (procesa relleno, puede devolver texto)

        return bufferPlano;
    }

    public byte[] descifrarDatosRSAPublica(PublicKey clave, byte[] b) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        cifrador.init(Cipher.DECRYPT_MODE, clave); // Descrifra con la clave privada

        System.out.println("Descifrar con clave publica");
        byte[] bufferPlano = cifrador.doFinal(b);
        System.out.println("TEXTO DESCIFRADO");
        return bufferPlano;

    }
    
    
    public byte[] descifrarDatosRSAPrivada(PrivateKey clave, byte[] b) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        cifrador.init(Cipher.DECRYPT_MODE, clave); // Descrifra con la clave privada

        System.out.println("Descifrar con clave privada");
        byte[] bufferPlano = cifrador.doFinal(b);
        System.out.println("TEXTO DESCIFRADO");
        return bufferPlano;

    }
    
    

    public byte[] resumirDatos(byte[] datos) throws NoSuchAlgorithmException, IOException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        messageDigest.update(datos); // Pasa texto de entrada a la funciÃ³n resumen

        byte[] resumen = messageDigest.digest(); // Completar el resumen
        return resumen;

    }
    
    public boolean compararResumenes(byte[] resumen1, byte[] resumen2){
        
       boolean toret=true;
       if(resumen1.length != resumen2.length)
           toret=false;
       
       for(int i=0;i<resumen1.length;i++){
           if(compare(resumen1[i], resumen2[i])!=0){
               return false;
           }    
       }        
       return toret;        
    }

}
