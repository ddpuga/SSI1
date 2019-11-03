/*
 * To change this license header, choose License Headers in Project Properties.
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
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

        
        //Descomentar en caso de no querer introducir argumentos
        //args = new String[]{"paquete.txt", "2", "albergue1", "albergue1.publica", "albergue2", "albergue2.publica", "oficina.publica", "oficina.privada", "peregrino.publica"};

        if (args.length < 4) {
            System.out.println("Al menos 4 parametros");
            System.exit(1);
        }

        Scanner teclado = new Scanner(System.in);
        Utils u = new Utils();

        System.out.println("Oficina, introduce nombre: ");
        String nombre = teclado.nextLine();

        Oficina ofi = new Oficina(nombre);

        Paquete p = PaqueteDAO.leerPaquete(args[0]);
        int numAlbergues = Integer.parseInt(args[1]); //Numero de albergues

        //List<PublicKey> listaPublicas = new ArrayList<>();
        Map<String, PublicKey> mapaPublicas = new HashMap<>();
        for (int i = 2; i < (2 + (numAlbergues * 2)); i += 2) { //Empieza en la posicion 2 y revisa todos los pares id-clave
            String idAlbAux = args[i];
            PublicKey clavePublica = u.leerPublica(args[i + 1]);

            mapaPublicas.put(idAlbAux, clavePublica);
        }

        int indexClavesArgs = 2 + (numAlbergues * 2);

        PublicKey publicaOficina = u.leerPublica(args[indexClavesArgs]);
        PrivateKey privadaOficina = u.leerPrivada(args[indexClavesArgs + 1]);
        PublicKey publicaPeregrino = u.leerPublica(args[indexClavesArgs + 2]);

        byte[] bloqueKS = p.getContenidoBloque("claveCifradaPeregrino");
        SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
        byte[] claveSecretaArray = ofi.descifrarDatosRSAPrivada(privadaOficina, bloqueKS);

        DESKeySpec DESspec = new DESKeySpec(claveSecretaArray);
        //Obtenemos la clave secreta
        SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);

        //Obtenemos los datos del peregrino aun encriptados
        byte[] datosPeregrinoEncriptados = p.getContenidoBloque("datosPeregrino");

        //Desciframos los datos con la clave secreta DES
        byte[] datosDesencriptados = ofi.descifrarDatosSimetrico(claveSecreta, datosPeregrinoEncriptados);

        //Resumimos los datos recibidos
        byte[] resumenGenerado = ofi.resumirDatos(datosDesencriptados);

        byte[] bloqueResumenEncriptado = p.getContenidoBloque("resumenPeregrino");
        byte[] resumenRecibido = ofi.descifrarDatosRSAPublica(publicaPeregrino, bloqueResumenEncriptado);

        //Comparamos los resumenes
        if (ofi.compararResumenes(resumenGenerado, resumenRecibido)) {
            System.out.println("RESUMENES COINCIDENTES, DATOS EN BUEN ESTADO");
        } else {
            System.out.println("ResumenGenerado: \n" + new String(resumenGenerado));
            System.out.println("ResumenRecibido: \n" + new String(resumenRecibido));
            System.out.println("DATOS COMPROMETIDOS :(");
        }

        System.out.println("------------------------------------------");
        Set setIds = mapaPublicas.keySet();
        Iterator<String> itSet = setIds.iterator();
        while (itSet.hasNext()) {
            String id = itSet.next();
            PublicKey clavePublicaAlbergue = mapaPublicas.get(id);

            //Datos encriptados
            byte[] datosAlbergueEncriptados = p.getContenidoBloque(id + "_datosAlbergue");
            //Clave secreta encriptada
            byte[] claveCifrada = p.getContenidoBloque(id + "_claveCifradaAlbergue");

            //Resumen recibido encriptado
            byte[] resumenCifrado = p.getContenidoBloque(id + "_resumenAlbergue");

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
            PublicKey publicaAlbergue = mapaPublicas.get(id);

            byte[] resumenRecibidoAlb = ofi.descifrarDatosRSAPublica(publicaAlbergue, resumenCifrado);
            System.out.println("Resultado descifrado del albergue: " + id);
            //Comparamos resumenes
            if (ofi.compararResumenes(resumenGeneradoAlb, resumenRecibidoAlb)) {
                System.out.println("RESUMENES DE ALBERGUE COINCIDENTES, DATOS DE ALBERGUE EN BUEN ESTADO");
                System.out.println(new String(datosAlbergue));
            } else {
                System.out.println("ResumenGenerado: \n" + new String(resumenGeneradoAlb));
                System.out.println("ResumenRecibido: \n" + new String(resumenRecibidoAlb));
                System.out.println("DATOS DE ALBERGUE COMPROMETIDOS :(");
            }
            System.out.println("------------------------------------------");
        }
        System.out.println("FIN PROGRAMA");
    }

}
