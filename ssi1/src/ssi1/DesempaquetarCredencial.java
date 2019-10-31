/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssi1;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author danid
 */
public class DesempaquetarCredencial {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //REGISTRAMOS EL PROVIDER
        Security.addProvider(new BouncyCastleProvider()); 
         
        args = new String[]{"paquete.txt", "oficina.publica", "oficina.privada", "peregrino.publica", "albergue1.publica", "albergue2.publica"};
        Scanner teclado = new Scanner(System.in);
        Utils u = new Utils();

        System.out.println("Oficina, introduce nombre: ");
        String nombre = teclado.nextLine();

        Oficina ofi = new Oficina(nombre);

        PublicKey publicaOficina = u.leerPublica(args[1]);
        PrivateKey privadaOficina = u.leerPrivada(args[2]);
        PublicKey publicaPeregrino = u.leerPublica(args[3]);
        PublicKey publicaAlbergue1 = u.leerPublica(args[4]);
        PublicKey publicaAlbergue2 = u.leerPublica(args[5]);

        Paquete p = PaqueteDAO.leerPaquete(args[0]);
        
        byte[] bloqueKS = p.getContenidoBloque("claveCifrada");
        SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
        byte[] claveSecretaArray = ofi.descifrarDatosRSAPrivada(privadaOficina, bloqueKS);

        DESKeySpec DESspec = new DESKeySpec(claveSecretaArray);
        //Obtenemos la clave secreta
        SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);   //Desencriptamos el bloque con la clave secreta cifrada
        
        //Desciframos los datos con la clave secreta DES
        byte[]datosDesencriptados = ofi.descifrarDatosSimetrico(claveSecreta, bloqueKS);
        //Resumimos los datos recibidos
        byte[]resumenGenerado = ofi.resumirDatos(datosDesencriptados);
        
        byte[] bloqueResumenEncriptado = p.getContenidoBloque("resumenPeregrino");
        byte[] resumenRecibido = ofi.descifrarDatosRSAPublica(publicaPeregrino, bloqueResumenEncriptado);
        
        //Comparamos los resumenes
        if(ofi.compararResumenes(resumenGenerado, resumenRecibido)){
            System.out.println("RESUMENES COINCIDENTES, DATOS EN BUEN ESTADO");
        }else{
            System.out.println("DATOS COMPROMETIDOS :(");
        }

    }

}
