package com.example.secure_chat_app;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private ObjectOutputStream sOutput;
    private ObjectInputStream sInput;

    private Socket socket;
    private final String server;
    private final int port;
    private Cipher cipher2;
    int i = 0;
    chat m;
    SecretKey AESkey;
    chat toSend;
    static String IV = "INFORMATIONSECUR";


    Client (String server, int port){
        this.server = server;
        this.port = port;
    }





    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Scanner scan = new Scanner(System.in);
        System.out.println("Connecting to the Server...");
        Socket clientSocket = new Socket("127.0.0.1", 7777);
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        // Client enters ID. This will be used by the program for verifying who
        // is communicating as well as check the OTP against the ID, on the
        // server side
        System.out.println("===================================");
        System.out.println("Please LogIn to Secured Chat App.");
        System.out.println("===================================");
        System.out.println("Username: ");
        String name = scan.nextLine();
        System.out.println("Enter your email: ");
        String id = scan.nextLine();
        System.out.println("Enter password: ");
        String psw = scan.nextLine();
        System.out.println("Contacting the Server...");
        out.println(id);
        System.out.println("Server has sent the OTP to "+ id);
        System.out.println("Please enter the OTP here: ");
        String otp = scan.nextLine();
        System.out.println("Verifying the user...");
        System.out.println("Hello "+ name + ","+ "Welcome to chat app!" );
        out.println(id);
        out.println(otp);
        System.out.println(in.readLine());


        String serverAddress;

        int portNumber = 7777;
        if(args.length < 1){
            System.out.println(":::::::::::::::::::::::::::::::::::::::::::::::::::::::");


            serverAddress = "127.0.0.1";
        }
        else{
            serverAddress = args[0];
        }
        Client client = new Client(serverAddress, portNumber);
        //generate symmetric key from client
        client.generateAESkey();
        client.start();


    }



    void start() throws IOException{
        socket = new Socket(server, port);
        System.out.println("Connection Accepted via " + socket.getInetAddress() + " :"  + socket.getPort());


        sInput = new ObjectInputStream(socket.getInputStream());
        sOutput = new ObjectOutputStream(socket.getOutputStream());

        new sendToServer().start();
        new listenFromServer().start();
    }



    class listenFromServer extends Thread {
        public void run(){
            while(true){
                try{
                    m = (chat) sInput.readObject();
                    decryptMessage(m.getData());
                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("connection closed");
                }
            }
        }
    }


    class sendToServer extends Thread {
        public void run(){
            while(true){
                try{

                    if (i == 0){
                        toSend = null;
                        toSend = new chat(encryptAESKey());
                        sOutput.writeObject(toSend);
                        i =1;
                    }

                    else{

                        System.out.println("CLIENT: Enter message to send for Server: ");
                        Scanner sc = new Scanner(System.in);
                        String s = sc.nextLine();
                        toSend = new chat(encryptMessage(s));
                        sOutput.writeObject(toSend);
                    }

                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("No message has been sent to Server");
                    break;
                }
            }
        }
    }

    void generateAESkey() throws NoSuchAlgorithmException {
        AESkey = null;
        KeyGenerator Gen = KeyGenerator.getInstance("AES");
        Gen.init(128);
        AESkey = Gen.generateKey();
        byte[] aesKey = AESkey.getEncoded();
        System.out.println(">AESKey length: " + aesKey.length);
        System.out.println(">AESKey: " + Arrays.toString(aesKey));
        String aesKeyBase64 = Base64.getEncoder().encodeToString(aesKey);
        System.out.println(">AESKeyBase64: " + aesKeyBase64);
    }


    private byte[] encryptAESKey (){
        Cipher cipher1 = null;
        byte[] key = null;
        try
        {
            PublicKey pK = readPublicKeyFromFile();
            System.out.println("Encrypting AES key using RSA Public Key: " + pK);
            cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher1.init(Cipher.ENCRYPT_MODE, pK );
            key = cipher1.doFinal(AESkey.getEncoded());
            i = 1;
        }

        catch(Exception e ) {
            System.out.println ( "Exception encoding key: " + e.getMessage() );
            e.printStackTrace();
        }
        return key;
    }


    private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException{
        cipher2 = null;
        byte[] cipherText = null;
        cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()) );
        long time3 = System.nanoTime();
        cipherText = cipher2.doFinal(s.getBytes());
        return cipherText;
    }


    private void decryptMessage(byte[] encryptedMessage) {
        cipher2 = null;
        try
        {
            cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
            byte[] msg = cipher2.doFinal(encryptedMessage);
            System.out.println("CLIENT: Enter message to send for Server: " + new String(msg));
            System.out.println("CLIENT: Enter message to send for Server: ");
        }

        catch(Exception e)
        {
            e.getCause();
            e.printStackTrace();
            System.out.println ( "Exception in data decryption:"  + e.getMessage() );
        }
    }


    public void closeSocket() {
        try{
            if(sInput !=null) sInput.close();
            if(sOutput !=null) sOutput.close();
            if(socket !=null) socket.close();
        }catch (IOException ioe){
            System.out.println("Problem in disconnecting..");
        }
    }


    PublicKey readPublicKeyFromFile() throws IOException {

        FileInputStream in = new FileInputStream("public.key");

        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m, e);

            KeyFactory kF = KeyFactory.getInstance("RSA");
            return kF.generatePublic(keySpecifications);
        } catch (Exception e) {
            throw new RuntimeException("Problem in Public Key reading..", e);
        }
    }

}
