# Proyecto final DAGSS 2019
Proyecto Java EE 7 


# PREVIO

* Instalación de NetBeans JEE (versión 8.2) con Servidor de Aplicaciones GlassFish (versión 4.1.1)
  * _Descarga_: [https://netbeans.org/downloads/8.2/](https://netbeans.org/downloads/8.2/)
  * _Pendiente_: Instalación con Netbeans 11 y Payara 5

* Descargar driver JDBC de MySQL y copiarlo en el directorio de librerias de GlassFish
   ```
   cd /tmp

   wget https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-8.0.18.zip

   unzip mysql-connector-java-8.0.18.zip

   cp mysql-connector-java-8.0.18/mysql-connector-java-8.0.18.jar \
      $HOME/glassfish-4.1.1/glassfish/domains/domain1/lib/

   pushd
   ```

* Descargar copia del proyecto desde GitHub
   ```
   git clone https://github.com/dagss2019/facturaaas.git
   ```


* Crear base de datos `facturaaas` en MySQL
   ```
   $ mysql -u root -p    [pedirá la contraseña de MySQL]

   mysql> create user facturaaas@localhost identified by "facturaaas";
   mysql> create database facturaaas;
   mysql> grant all privileges on facturaaas.* to facturaaas@localhost;
   ```
   
   Adicionalmente, puede ser necesario establecer un formato de fecha compatible
   ```
   mysql> set @@global.time_zone = '+00:00';
   mysql> set @@session.time_zone = '+00:00';
   ```

* Crear tabla de usuarios y cargar usuarios iniciales

  * Desde el directorio `facturaaas`
  
  ```
  cd facturaaas

  mysql -u facturaaas -p -D facturaaas < sql/usuarios_iniciales.sql
                <pedirá la contraseña facturaaaas>
  ```
  
* Abrir el proyecto y ejecutarlo
En el primer despligue se generarán el resto de tablas de la base de datos.
* En caso de incorporar nuevas entidades, también se generán sus respectivas tablas una vez desplegada la nueva versión de la aplicación.
* Dependiendo de las modificacionesr realiazdas sobre entidades existentes (bien las de partida o las incorporadas posteriormente) puede requerirse eliminar manualmente las 
tablas implicadas (o la BD completa) para que el motor JPA vuelva a generarlas.

