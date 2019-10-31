/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssi1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import static java.lang.System.in;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 *
 * @author danid
 */
public class Utils {
    
    public Utils(){
    }
    
    
    public static PublicKey leerPublica(String ruta) throws FileNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException{
       
        
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
        
        File ficheroClavePublica = new File(ruta); 
		int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
		byte[] bufferPub = new byte[tamanoFicheroClavePublica];
            FileInputStream in = new FileInputStream(ficheroClavePublica);
		in.read(bufferPub, 0, tamanoFicheroClavePublica);
		in.close();
        
                X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
		PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
                return clavePublica;
        
    }
    
    public static PrivateKey leerPrivada(String ruta) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
        
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        
        File ficheroClavePrivada = new File(ruta); 
		int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
		byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
		FileInputStream in = new FileInputStream(ficheroClavePrivada);
		in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
		in.close();

		// 2.2 Recuperar clave privada desde datos codificados en formato PKCS8
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
		PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
                
                return clavePrivada;
        
    }
    
}
