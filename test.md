package com.almahari;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

public class ServerTest2 {
    public static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String response = "This is the response";
            HttpsExchange httpsExchange = (HttpsExchange) t;
            t.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            t.sendResponseHeaders(200, response.getBytes().length);
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        try {
            // setup the socket address
            InetSocketAddress address = new InetSocketAddress(8000);

            // initialise the HTTPS server
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // initialise the keystore
            char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            //generate key [keytool -genkeypair -keyalg RSA -alias selfsigned -keystore testkey.jks -storepass password -validity 360 -keysize 2048]
            //https://www.javacodegeeks.com/2014/07/java-keystore-tutorial.html
            FileInputStream fis = new FileInputStream("D:\\development\\java\\ReactiveCodeTest\\src\\main\\resources\\testkey.jks");
            ks.load(fis, password);

            // setup the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            // setup the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            // setup the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        // initialise the SSL context
                        SSLContext context = getSSLContext();
                        SSLEngine engine = context.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        // Set the SSL parameters
                        SSLParameters sslParameters = context.getSupportedSSLParameters();
                        params.setSSLParameters(sslParameters);

                    } catch (Exception ex) {
                        System.out.println("Failed to create HTTPS port");
                    }
                }
            });
            httpsServer.createContext("/test", new MyHandler());
            httpsServer.setExecutor(null); // creates a default executor
            httpsServer.start();

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 8000 + " of localhost");
            exception.printStackTrace();

        }
    }
}

/*
Create Keystore, Keys and Certificate Requests

Generate a Java keystore and key pair
1
keytool -genkey -alias mydomain -keyalg RSA -keystore keystore.jks -storepass password
Generate a certificate signing request (CSR) for an existing Java keystore
1
keytool -certreq -alias mydomain -keystore keystore.jks -storepass password -file mydomain.csr
Generate a keystore and self-signed certificate
1
keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360
Import Certificates

Import a root or intermediate CA certificate to an existing Java keystore
1
keytool -import -trustcacerts -alias root -file Thawte.crt -keystore keystore.jks -storepass password
Import a signed primary certificate to an existing Java keystore
1
keytool -import -trustcacerts -alias mydomain -file mydomain.crt -keystore keystore.jks -storepass password

Export Certificates

Export a certificate from a keystore
1
keytool -export -alias mydomain -file mydomain.crt -keystore keystore.jks -storepass password
Check/List/View Certificates

Check a stand-alone certificate
1
keytool -printcert -v -file mydomain.crt
Check which certificates are in a Java keystore
1
keytool -list -v -keystore keystore.jks -storepass password
Check a particular keystore entry using an alias
1
keytool -list -v -keystore keystore.jks -storepass password -alias mydomain
Delete Certificates

Delete a certificate from a Java Keytool keystore
1
keytool -delete -alias mydomain -keystore keystore.jks -storepass password
Change Passwords

Change a Java keystore password
1
keytool -storepasswd -new new_storepass -keystore keystore.jks -storepass password
Change a private key password
1
keytool -keypasswd -alias client -keypass old_password -new new_password -keystore client.jks -storepass password



10. Configure SSL using Keystores and Self Signed Certificates on Apache Tomcat
Generate new keystore and self-signed certificateusing this command, you will prompt to enter specific information such as user name, organization unit, company and location.
1
keytool -genkey -alias tomcat -keyalg RSA -keystore /home/ashraf/Desktop/JavaCodeGeek/keystore.jks -validity 360
Java KeyStore Tutorial_html_m5d3841d

You can list the certificate details you just created using this command
1
keytool -list -keystore /home/ashraf/Desktop/JavaCodeGeek/keystore.jks
Java KeyStore Tutorial_html_131ca506

Download Tomcat 7
Configure Tomcat’s server to support for SSL or https connection. Adding a connector element in Tomcat\conf\server.xml
1
2
<Connector port="8443" maxThreads="150" scheme="https" secure="true"
SSLEnabled="true" keystoreFile="/home/ashraf/Desktop/JavaCodeGeek/.keystore" keystorePass="password" clientAuth="false" keyAlias="tomcat" sslProtocol="TLS" />

 */
