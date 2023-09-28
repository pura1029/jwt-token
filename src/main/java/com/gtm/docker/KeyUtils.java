package com.gtm.docker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class KeyUtils {
    public static byte[] kidFromCryptoKey(String private_key_path, String key_type) throws Exception {
        try {
            Process process;
            if ("EC".equals(key_type)) {
                process = runOpenSSLCommand("openssl ec -in " + private_key_path + " -pubout -outform DER");
            } else if ("RSA".equals(key_type)) {
                process = runOpenSSLCommand("openssl rsa -in " + private_key_path + " -pubout -outform DER");
            } else {
                throw new Exception("Key type not supported");
            }

            if (process.exitValue() != 0) {
                String errorMsg = new String(process.getErrorStream().readAllBytes());
                throw new IOException("OpenSSL command failed with error: " + errorMsg);
            }

            return process.getInputStream().readAllBytes();
        } catch (IOException e) {
            throw new Exception("Error running OpenSSL command: " + e.getMessage());
        }
    }

    private static Process runOpenSSLCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        try {
            process.waitFor();
            return process;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("OpenSSL command was interrupted");
        }
    }

    public static void main(String[] args) {
        try {
            String private_key_path = "/Users/kumargautam/Git_repo/GitHub-test/jwt-token/src/main/resources/certs/cluster_key.pem";
            String key_type = "RSA"; // Change this to "RSA" if needed

            byte[] der = kidFromCryptoKey(private_key_path, key_type);
            // You can process the 'der' byte array as needed
            System.out.println(new String(der));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
