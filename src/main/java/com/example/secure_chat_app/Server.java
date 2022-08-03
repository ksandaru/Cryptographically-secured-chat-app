package com.example.secure_chat_app;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

public class Server {

    private ObjectOutputStream sOut;
    private ObjectInputStream sIn;
    SecretKey AESKey;
    int i;
    byte[] input;
    private chat m;
    int port;
    static String IV = "INFORMATIONSECUR";
    chat toSend;

    public Server(int port) {
        this.port = port;
    }


    public static void main(String[] args) throws IOException {

        int port = 7777;
        Server server = new Server(port);
        server.start();

    }


    void start() throws IOException {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server running and waiting for client...");
        Socket clientSocket = serverSocket.accept();
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        // Server waits for a client to send its user ID
        String id = in.readLine();

        // Server generates an OTP and waits for client to send this
        Random r = new Random();
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            otp.append(r.nextInt(10));
        }
        System.out.println("This is the OTP, sent to email: "+ otp);

        // Server starts a timer of 10 seconds during which the OTP is valid.
        TimeOutTask task = new TimeOutTask();
        Timer t1 = new Timer();
        t1.schedule(task, 100000L);

        // Server listens for client to send its ID and OTP to check if it is
        // valid
        String newId = in.readLine();
        String newOtp = in.readLine();
        if (newId.equals(id)) {
            // User ID is verified
            if (task.isTimedOut) {
                // User took more than 100 seconds and hence the OTP is invalid
                out.println("Time-Out!");
            } else if (!newOtp.equals(otp.toString())) {
                out.println("Incorrect OTP!");
                System.exit(0);
            } else {
                out.println("Logged In Successfully!");
            }
        }


        System.out.print("Receiver listening on the port " + port + ".");
        Socket socket = serverSocket.accept();  // accepting the connection.
        clientThread t = new clientThread(socket);
        t.start();
        serverSocket.close();
    }


    class clientThread extends Thread {
        Socket socket;

        clientThread(Socket socket) throws IOException {
            this.socket = socket;
            sOut = new ObjectOutputStream(socket.getOutputStream());
            sIn = new ObjectInputStream(socket.getInputStream());
            new listenFromClient().start();
            new sendToClient().start();
        }
    }


    class listenFromClient extends Thread {

        public void run() {

            while (true) {
                try {
                    m = (chat) sIn.readObject();

                } catch (ClassNotFoundException e) {
                    System.out.println("Class not found while reading the chat object");
                } catch (IOException e) {
                    e.printStackTrace();
                }

                if (i == 0) {
                    if (m.getData() != null) {
                        decryptAESKey(m.getData());
                        System.out.println();
                        i++;
                    } else {
                        System.out.println("Error in decrypting AES key in clientThread.run()");
                        System.exit(1);
                    }
                } else {
                    if (m.getData() != null) {
                        decryptMessage(m.getData());
                    }
                }
            }
        }
    }


    class sendToClient extends Thread {
        public void run() {
            while (true) {
                try {
                    System.out.println("Server: Enter message to send for Client: ");
                    Scanner sc = new Scanner(System.in);
                    String s = sc.nextLine();
                    toSend = null;
                    toSend = new chat(encryptMessage(s));
                    write();
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("No message  sent to the server");
                    break;
                }
            }
        }

        public synchronized void write() throws IOException {
            sOut.writeObject(toSend);
            sOut.reset();
        }
    }


    private void decryptAESKey(byte[] encryptedKey) {
        SecretKey key = null;
        PrivateKey pvtKey = null;
        Cipher keyDecipher = null;
        try {
            pvtKey = readPrivateKeyFromFile();
            keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            keyDecipher.init(Cipher.DECRYPT_MODE, pvtKey);
            key = new SecretKeySpec(keyDecipher.doFinal(encryptedKey), "AES");
            System.out.println();
            System.out.println(" AES key after decryption : " + key);
            byte[] aesK = key.getEncoded();
            System.out.println("AESKey length: " + aesK.length);
            System.out.println("AESKey: " + Arrays.toString(aesK));
            String aesKBase64 = Base64.getEncoder().encodeToString(aesK);
            System.out.println("aesKeyBase64: " + aesKBase64);
            i = 1;
            AESKey = key;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception found when decrypting the AES key: " + e.getMessage());
        }

    }


    private void decryptMessage(byte[] encryptedMessage) {
        Cipher serverDecryptCipher = null;
        try {
            serverDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            serverDecryptCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
            byte[] msg = serverDecryptCipher.doFinal(encryptedMessage);
            System.out.println("Server: Received message from Client: " + new String(msg));
            System.out.println("Server: Enter message to send for Client: ");
        } catch (Exception e) {
            e.getCause();
            e.printStackTrace();
            System.out.println("Exception found when decrypting:" + e.getMessage());
        }
    }


    private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        Cipher serverEncryptCipher = null;
        byte[] cipherText = null;
        serverEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        serverEncryptCipher.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
        cipherText = serverEncryptCipher.doFinal(s.getBytes());
        return cipherText;
    }


    PrivateKey readPrivateKeyFromFile() throws IOException {

        FileInputStream in = new FileInputStream("private.key");

        try (ObjectInputStream readObj = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger m = (BigInteger) readObj.readObject();
            BigInteger d = (BigInteger) readObj.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, d);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Error with reading the private key", e);
        }
    }


}

class TimeOutTask extends TimerTask {
    boolean isTimedOut = false;

    public void run() {
        isTimedOut = true;
    }
}
