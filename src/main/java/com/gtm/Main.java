package com.gtm;


import com.gtm.docker.KeyUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.PemException;

import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Insert your comment for {@link Main}.
 *
 * @author kumargautam
 */
public class Main {

    private static String private_key_path = "/Users/kumargautam/Git_repo/GitHub-test/jwt-token/src/main/resources/certs/cluster_key.pem";

    public static void main(String[] args) throws Exception {
        JwtUtil jwtUtil = new JwtUtil();
        PrivateKey privateKey=getPrivateKeyFromPemFile();
        System.out.println(privateKey.getAlgorithm());
        System.out.println(jwtUtil.generateCustomJwt(getPrivateKey()));
    }

    public static PublicKey readX509PublicKey() {
        try {
            InputStream clusterCertFile = Main.class.getResourceAsStream("server.crt");
            CertificateFactory x509Fact = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) x509Fact.generateCertificate(clusterCertFile);
            return cert.getPublicKey();
        } catch (Exception e) {
            throw new RuntimeException("Issue in getting/parsing token public key from the file system");
        }
    }

    public static PrivateKey getPrivateKeyFromPemFile() throws URISyntaxException {
        try (PEMParser pemParser = new PEMParser(new FileReader(private_key_path))) {
            System.out.println("Extract Private Key from PEM file");
            Object obj;
            PrivateKey privateKey = null;
            while ((obj = pemParser.readObject()) != null) {
                // RSA, DSA and EC PRIVATE KEY
                if (obj instanceof PEMKeyPair) {
                    PEMKeyPair keyPair = (PEMKeyPair) obj;
                    PrivateKeyInfo privateKeyInfo = keyPair.getPrivateKeyInfo();
                    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
                    privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
                }
                // PRIVATE KEY
                if (obj instanceof PrivateKeyInfo) {
                    JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
                    privateKey = jcaPEMKeyConverter.getPrivateKey((PrivateKeyInfo) obj);
                }
            }
            return privateKey;
        } catch (Exception e) {
            throw new RuntimeException("Issue in getting/parsing token private key from the file system");
        }
    }

    public static PrivateKey getPrivateKey() throws Exception {
        String pem = Files.readString(Paths.get(private_key_path));
        byte[] der = pemToDer(pem);
        PrivateKey privateKey = decodePrivateKey(der);
        return privateKey;
    }

    public static byte[] pemToDer(String pem) {
        try {
            pem = removeBeginEnd(pem);
            return Base64.decode(pem);
        } catch (IOException var3) {
            throw new PemException(var3);
        }
    }

    public static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }

    public static PrivateKey decodePrivateKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static byte[] pemToDer() throws Exception {
        return KeyUtils.kidFromCryptoKey(private_key_path, "RSA");
    }
}