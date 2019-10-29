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
import java.util.ArrayList;
import java.util.List;
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
         
        //---------------------------------LEER-----------------------------------
        /*
        El codigo tal y como lo tenemos tiene un problema, solo funciona para un albergue 
        porque hay que especificar de una manera u otra la clave del albergue en cuestion
        (Ver donde se declara resumenRecibidoAlb ) (linea 113 tal y como subire este commit)
        */
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
        
        byte[] bloqueKS = p.getContenidoBloque("claveCifradaPeregrino");
        SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
        byte[] claveSecretaArray = ofi.descifrarDatosRSAPrivada(privadaOficina, bloqueKS);

        DESKeySpec DESspec = new DESKeySpec(claveSecretaArray);
        //Obtenemos la clave secreta
        SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);  
        
        //Obtenemos los datos del peregrino aun encriptados
        byte[]datosPeregrinoEncriptados = p.getContenidoBloque("datosPeregrino");
        //Desciframos los datos con la clave secreta DES
        byte[]datosDesencriptados = ofi.descifrarDatosSimetrico(claveSecreta, datosPeregrinoEncriptados);
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
        
        //Ahora recuperamos los datos del albergue y verificamos su autenticidad
        List<String> listaNombres = p.getNombresBloque();
        //Buscamos los datos del albergue
        for(String cad: listaNombres){
            if(cad.contains("_datosAlbergue")){
                //Datos encriptados
                byte[] datosAlbergueEncriptados = p.getContenidoBloque(cad);
                //spliteo por la _ para recuperar el nombre pues el formato del id es nombre_tipoBloque
                String[] auxNom = cad.split("_");
                //Extraigo el nombre del array spliteado
                String nombreAlb = auxNom[0];
                System.out.println("Nombre albegue: " + nombreAlb);
                //Clave secreta encriptada
                byte[] claveCifrada = p.getContenidoBloque(nombreAlb+"_claveCifradaAlbergue");
                //Resumen recibido encriptado
                byte[] resumenCifrado = p.getContenidoBloque(nombreAlb+"_resumenAlbergue");
                
                //Desencriptamos
                
                byte[] claveSecretaAlbArray = ofi.descifrarDatosRSAPrivada(privadaOficina, claveCifrada);
                DESspec = new DESKeySpec(claveSecretaAlbArray);    //Reusamos el DESspec anterior
                //Clave secreta DES de Albergue
                SecretKey claveSecretaAlb = secretKeyFactoryDES.generateSecret(DESspec); 
                //Desciframos datos
                byte[] datosAlbergue = ofi.descifrarDatosSimetrico(claveSecretaAlb, datosAlbergueEncriptados);
                //Generamos un resumen de los datos recibidos
                byte[] resumenGeneradoAlb = ofi.resumirDatos(datosAlbergue);
                //Resumen recibido ya descifrado
                byte[] resumenRecibidoAlb = ofi.descifrarDatosRSAPublica(publicaAlbergue1, resumenCifrado);
                //Comparamos resumenes
                if(ofi.compararResumenes(resumenGeneradoAlb, resumenRecibidoAlb)){
                    System.out.println("RESUMENES DE ALBERGUE COINCIDENTES, DATOS EN BUEN ESTADO");
                }else{
                    System.out.println("DATOS DE ALBERGUE COMPROMETIDOS :(");
                }
            }
        }
        
    }


}
