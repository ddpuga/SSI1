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
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 *
 * @author danid
 */
public class DesempaquetarCredencial {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

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
        SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);

        ofi.descifrarDatosSimetrico(claveSecreta, bloqueKS);
        
        //desencriptar datos (simetrico) con clave secreta

    }

}
