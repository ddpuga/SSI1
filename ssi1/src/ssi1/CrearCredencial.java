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

/**
 *
 * @author danid
 */
public class CrearCredencial {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        
        args = new String[]{"paquete.txt","oficina.publica","peregrino.privada"};
        
        Scanner teclado = new Scanner(System.in);
        Utils u = new Utils();
        
        System.out.println("Peregrino, introduce nombre: ");
        String nombre = teclado.nextLine();
        System.out.println("Introduce dni: ");
        String dni = teclado.nextLine();
        System.out.println("Introduce motivo: ");
        String motivo = teclado.nextLine();
        System.out.println("Introduce domicilio: ");
        String domicilio = teclado.nextLine();
        System.out.println("Introduce fecha de creación");
        String fecha = teclado.nextLine();
        System.out.println("Introduce lugar de creación");
        String lugar = teclado.nextLine();
        
      
        Peregrino per = new Peregrino(nombre,dni,motivo,domicilio,fecha,lugar);
        
        PublicKey publicaOficina = u.leerPublica(args[1]);
        PrivateKey privadaPeregrino = u.leerPrivada(args[2]);
       Paquete p = per.crearCredencial(publicaOficina, privadaPeregrino);
        PaqueteDAO.escribirPaquete(p, args[0]);
        
    }
    
}
