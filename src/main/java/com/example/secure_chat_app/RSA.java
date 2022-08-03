package com.example.secure_chat_app;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSA {

    Key publicKey;
    Key privateKey;


    public static void main(String[] args) throws  GeneralSecurityException, IOException {

        System.out.println("Creating RSA class");
        RSA rsa = new RSA();
        rsa.createRSA();
    }


    void createRSA() throws GeneralSecurityException, IOException{
        KeyPairGenerator kPairGen = KeyPairGenerator.getInstance("RSA");
        kPairGen.initialize(1024);
        KeyPair kPair = kPairGen.genKeyPair();
        publicKey = kPair.getPublic();
        System.out.println("----------------------------");
        System.out.println("RSA public key: "+ publicKey);
        privateKey = kPair.getPrivate();

        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(kPair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec pvt = fact.getKeySpec(kPair.getPrivate(), RSAPrivateKeySpec.class);
        serializeToFile("public.key", pub.getModulus(), pub.getPublicExponent());
        serializeToFile("private.key", pvt.getModulus(), pvt.getPrivateExponent());

    }


    void serializeToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {

        try (ObjectOutputStream ObjOut = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)))) {
            ObjOut.writeObject(mod);
            ObjOut.writeObject(exp);
            System.out.println("Created key file: " + fileName);
        } catch (Exception e) {
            throw new IOException(" Exception when writing the key object", e);
        }
    }

}
