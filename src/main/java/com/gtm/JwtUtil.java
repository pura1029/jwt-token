/*
 * Copyright (c) 2023 VMware, Inc. All Rights Reserved.
 *
 */

package com.gtm;

import com.gtm.docker.DockerKeyIdentifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.common.crypto.CryptoIntegration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Insert your comment for {@link JwtUtil}.
 *
 * @author kumargautam
 */
public class JwtUtil {

    public JwtUtil(){
        //CryptoIntegration.init(this.getClass().getClassLoader());
    }

    public String generateCustomJwt(PrivateKey privateKey) throws Exception {
        JwsHeader header = new DefaultJwsHeader(new HashMap<>());
        header.setAlgorithm(SignatureAlgorithm.RS256.getValue());
        String keyId = DockerKeyIdentifier.generateKeyID(privateKey);//"WCMK:34H5:6NBN:3NJP:LFIM:2WI6:OODP:HMOQ:OTMK:57FN:PX35:RKKW"
        //String keyId = kidFromCryptoKey("/Users/kumargautam/Git_repo/GitHub-test/jwt-token/src/main/resources/certs/server.key", "RSA");
        header.setKeyId(keyId);
        header.setType("JWT");

        Instant now = Instant.now();
        Claims claims = new DefaultClaims();
        claims.setIssuer("demo_oauth");
        claims.setSubject("admin");
        claims.setAudience("demo_registry");
        claims.setExpiration(Date.from(now.plusSeconds(3600)));
        claims.setNotBefore(Date.from(now.minusSeconds(30)));
        claims.setIssuedAt(Date.from(now));

        Map<String, Object> accessClaim = new HashMap<>();
        accessClaim.put("type", "registry");
        accessClaim.put("name", "catalog");
        accessClaim.put("actions", new String[]{"*"});
        claims.put("access", new Object[]{accessClaim});

        String jwtToken = Jwts.builder()
                .setHeader((Map<String, Object>) header)
                .setClaims(claims)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        return jwtToken;
    }

    public static String generateKeyID(PrivateKey privateKey) {
        try {
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(privateKey.getEncoded());
            byte[] derBytes = x509KeySpec.getEncoded();

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(derBytes);
            byte[] hashBytes = sha256.digest();

            // Truncate the hash to 240 bits (30 bytes)
            byte[] truncatedHash = new byte[30];
            System.arraycopy(hashBytes, 0, truncatedHash, 0, truncatedHash.length);

            return keyIDEncode(truncatedHash);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String kidFromCryptoKey(String privateKeyPath, String keyType) throws Exception {
        MessageDigest algorithm;
        try {
            algorithm = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("SHA-256 algorithm not available", e);
        }

        byte[] der;
        try {
            if ("EC".equals(keyType)) {
                der = runCommand("openssl", "ec", "-in", privateKeyPath, "-pubout", "-outform", "DER");
            } else if ("RSA".equals(keyType)) {
                der = runCommand("openssl", "rsa", "-in", privateKeyPath, "-pubout", "-outform", "DER");
            } else {
                throw new Exception("Key type not supported");
            }
        } catch (IOException | InterruptedException e) {
            throw new Exception("Error running OpenSSL command", e);
        }

        if (der == null) {
            throw new Exception("Failed to generate DER");
        }

        algorithm.update(der);
        // Truncate the hash to 240 bits (30 bytes)
        byte[] truncatedHash = new byte[30];
        System.arraycopy(algorithm.digest(), 0, truncatedHash, 0, truncatedHash.length);

        return keyIDEncode(truncatedHash);
    }

    public static byte[] runCommand(String... command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process = processBuilder.start();

        if (process.waitFor() != 0) {
            throw new IOException("Command execution failed");
        }

        return Files.readAllBytes(Paths.get(command[command.length - 1]));
    }

    private static String keyIDEncode(byte[] bytes) {
        String base32Encoded = base32Encode(bytes);
        base32Encoded = StringUtils.stripEnd(base32Encoded, "=");
        //base32Encoded = base32Encoded.replaceAll("=", ""); // Remove trailing '=' characters

        StringBuilder encodedBuffer = new StringBuilder();
        int i;
        for (i = 0; i < base32Encoded.length() / 4 - 1; i++) {
            int start = i * 4;
            int end = start + 4;
            encodedBuffer.append(base32Encoded.substring(start, end)).append(":");
        }
        encodedBuffer.append(base32Encoded.substring(i * 4));

        return encodedBuffer.toString();
    }

    private static String base32Encode(byte[] bytes) {
        String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        StringBuilder encoded = new StringBuilder();
        int bitBuffer = 0;
        int bitCount = 0;

        for (byte b : bytes) {
            bitBuffer = (bitBuffer << 8) | (b & 0xFF);
            bitCount += 8;

            while (bitCount >= 5) {
                int index = (bitBuffer >> (bitCount - 5)) & 0x1F;
                encoded.append(BASE32_ALPHABET.charAt(index));
                bitCount -= 5;
            }
        }

        // Handle any remaining bits
        if (bitCount > 0) {
            int index = (bitBuffer << (5 - bitCount)) & 0x1F;
            encoded.append(BASE32_ALPHABET.charAt(index));
        }

        return encoded.toString();
    }

    private static String keyIDEncode1(byte[] bytes) {
        // Encode the bytes using base32
        String source = Base64.getEncoder().encodeToString(bytes);

        // Remove trailing '=' characters
        source = source.replaceAll("=", "");

        // Split the string into groups of 4 characters separated by ':'
        StringBuilder keyId = new StringBuilder();
        for (int i = 0; i < source.length(); i += 4) {
            int endIndex = Math.min(i + 4, source.length());
            keyId.append(source, i, endIndex);
            if (endIndex < source.length()) {
                keyId.append(':');
            }
        }

        return keyId.toString();
    }
}
