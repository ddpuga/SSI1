/* * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
 /*Este codigo ha sido desarrollado por:
    Daniel Duque Puga
    Miguel Crecente Rodriguez
    Rodrigo Curras Ferradas
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
        /*
            EJECUTAR 2 veces SellarCredencial, una para albergue1 y otra para albergue2
         */
        
        //Descomentar en caso de no querer introducir argumentos
        //args = new String[]{"paquete.txt", "albergue1", "oficina.publica", "albergue1.privada"}; //PARA EL ALBERGUE 1
        //Descomentar en caso de no querer introducir argumentos
        //args = new String[]{"paquete.txt", "albergue2", "oficina.publica", "albergue2.privada"}; //PARA EL ALBERGUE 2
        Scanner teclado = new Scanner(System.in);
        Utils u = new Utils();

        String id = args[1];    //Capturamos el identificador del albergue

        System.out.println("Albergue, introduce nombre: ");
        String nombre = teclado.nextLine();
        System.out.println("Introduce fecha de creacion");
        String fecha = teclado.nextLine();
        System.out.println("Introudce lugar de creacion");
        String lugar = teclado.nextLine();
        System.out.println("Introduce incidencias: ");
        String incidencias = teclado.nextLine();

        Albergue alb = new Albergue(id, nombre, fecha, lugar, incidencias);

        PublicKey publicaOficina = u.leerPublica(args[2]);
        PrivateKey privadaAlbergue = u.leerPrivada(args[3]);
        Paquete p = PaqueteDAO.leerPaquete(args[0]);
        p = alb.sellarCredencial(publicaOficina, privadaAlbergue, p);

        PaqueteDAO.escribirPaquete(args[0], p);

    }
}
