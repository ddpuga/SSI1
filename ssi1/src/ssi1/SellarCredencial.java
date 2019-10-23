/* * To change this license header, choose License Headers in Project Properties.
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author danid
 */
public class SellarCredencial {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //REGISTRAMOS EL PROVIDER
        Security.addProvider(new BouncyCastleProvider()); 
        
        args = new String[]{"paquete.txt", "oficina.publica", "albergue.privada"};
        Scanner teclado = new Scanner(System.in);
        Utils u = new Utils();

        System.out.println("Albergue, introduce nombre: ");
        String nombre = teclado.nextLine();
        System.out.println("Introduce fecha de creacion");
        String fecha = teclado.nextLine();
        System.out.println("Introudce lugar de creacion");
        String lugar = teclado.nextLine();
        System.out.println("Introduce incidencias: ");
        String incidencias = teclado.nextLine();

        Albergue alb = new Albergue(nombre, fecha, lugar, incidencias);

        PublicKey publicaOficina = u.leerPublica(args[1]);
        PrivateKey privadaAlbergue = u.leerPrivada(args[2]);
        Paquete p = PaqueteDAO.leerPaquete(args[0]);
        p = alb.sellarCredencial(publicaOficina, privadaAlbergue, p);

        PaqueteDAO.escribirPaquete(args[0],p);

    }
}
