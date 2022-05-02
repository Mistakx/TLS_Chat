package Client;

import Encryption.Algorithms.AES;
import Encryption.Algorithms.EncryptionAlgorithm;
import Encryption.Algorithms.RSA;
import Encryption.Encryption;
import Message.Handshake;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;

import Encryption.SymmetricEncryption;
import Encryption.AsymmetricEncryption;
import Encryption.DiffieHellman;
import Message.Message;
import Message.MessageType;

import static java.lang.System.exit;

public class Client {

    /**
     * The client socket to connect to the server.
     */
    private final Socket clientSocket;
    /**
     * The input stream to read from the server.
     */
    private final ObjectInputStream inputStream;
    /**
     * The output stream to write to the server.
     */
    private final ObjectOutputStream outputStream;

    /**
     * The chosen encryption functions.
     */
    private Encryption clientEncryption;
    /**
     * The client's handshake information.
     */
    private Handshake clientHandshake = new Handshake(null, null, null, null, null);
    private PublicKey serverAsymmetricPublicKey;
    private byte[] clientDiffieHellmanPrivateSharedKey;

    /**
     * The settings menu to change the client's settings.
     */
    private void optionsMenu() {
        EncryptionAlgorithm chosenEncryptionAlgorithm = new RSA();
        String chosenEncryptionAlgorithmType = chosenEncryptionAlgorithm.getType();
        String chosenEncryptionAlgorithmName = chosenEncryptionAlgorithm.getName();
        int chosenEncryptionKeySize = chosenEncryptionAlgorithm.getKeySizes().get(0);
        clientHandshake = new Handshake(clientHandshake.username(), chosenEncryptionAlgorithmType, chosenEncryptionAlgorithmName, chosenEncryptionKeySize, clientHandshake.publicKey());

        if (clientHandshake.encryptionAlgorithmType().equals("Symmetric")) {
            clientEncryption = new SymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            clientHandshake = new Handshake(clientHandshake.username(), clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey());
        } else if (clientHandshake.encryptionAlgorithmType().equals("Asymmetric")) {
            clientEncryption = new AsymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) clientEncryption;
            clientHandshake = new Handshake(clientHandshake.username(), clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), asymmetricEncryption.getPublicKey());
        }

    }

    /**
     * Sends this client's username and chosen encryption information to the server.
     *
     * @throws IOException
     */
    private void startServerHandshake() throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {

        if (clientHandshake.encryptionAlgorithmName() == null) {
            System.out.println("Encryption algorithm not chosen yet.");
            return;
        } else if (clientHandshake.encryptionKeySize() == 0) {
            System.out.println("Encryption algorithm size not chosen yet.");
            return;
        }

        Handshake handshake;
        if (clientEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
            System.out.println("Started asymmetric encryption handshake.");
            PublicKey publicKey = asymmetricEncryption.getPublicKey();
            handshake = new Handshake(clientHandshake.username(), "Asymmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), publicKey);
            outputStream.writeObject(handshake);
            // The server's public key is sent to the client already encrypted.
        } else if (clientEncryption instanceof SymmetricEncryption) {
            System.out.println("Started symmetric encryption handshake.");
            DiffieHellman diffieHellman = new DiffieHellman();
            PrivateKey privateKey = diffieHellman.generatePrivateKey();
            PublicKey publicKey = diffieHellman.generatePublicKey();
            handshake = new Handshake(clientHandshake.username(), "Symmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), publicKey);
            outputStream.writeObject(handshake);
            outputStream.flush();
            PublicKey clientPublicKey = (PublicKey) inputStream.readObject();
            clientDiffieHellmanPrivateSharedKey = diffieHellman.computePrivateKey(clientPublicKey, clientHandshake.encryptionKeySize());
            System.out.println("Server and client agreed on private key: ");
            System.out.println(new String(clientDiffieHellmanPrivateSharedKey));
        }

    }

    private void changeUsername() {
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Enter new username: ");
        String newUsername = inputScanner.nextLine();
        clientHandshake = new Handshake(newUsername, clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey());
    }

    public Client(String host, int port) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {

        clientSocket = new Socket(host, port);
        outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        inputStream = new ObjectInputStream(clientSocket.getInputStream());

        changeUsername();
        optionsMenu();
        System.out.println("\nStarted server handshake.");
        startServerHandshake();
        System.out.println("Ended server handshake.");

    }

    /**
     * Continuously accept user input and send it to the server.
     *
     * @throws IOException
     */
    public void sendMessages() throws Exception {

        // Waits for the client to get the server's public key
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.println("\n" + clientHandshake.username() + ": ");
            String messageText = inputScanner.nextLine();
            Message message = new Message(MessageType.Message, clientHandshake.username(), messageText, null, null);
            byte[] messageBytes = message.toBytes();
            byte[] encryptedMessage = new byte[0];
            if (clientEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                encryptedMessage = asymmetricEncryption.encryptMessage(messageBytes, serverAsymmetricPublicKey);
            } else if (clientEncryption instanceof SymmetricEncryption symmetricEncryption) {
                encryptedMessage = symmetricEncryption.do_SymEncryption(messageBytes, clientDiffieHellmanPrivateSharedKey);
//                byte[] decryptedMessage = symmetricEncryption.do_SymDecryption(encryptedMessage, clientDiffieHellmanPrivateSharedKey);
//                System.out.println("\nDecrypted message: ");
//                System.out.println(new String(decryptedMessage));
            }
            System.out.println("\nDecrypted message bytes: ");
            System.out.println(new String(messageBytes));
            System.out.println("Encrypted message bytes sent: ");
            System.out.println(new String(encryptedMessage));
            outputStream.writeObject(encryptedMessage);
        }


    }


    /**
     * Continuously read the messages sent to this client's socket.
     */
    public void readMessages() {

        new Thread(() -> {

            while (clientSocket.isConnected()) {

                try {

                    byte[] encryptedMessage = (byte[]) inputStream.readObject();
                    System.out.println("\nReceived encrypted message bytes: ");
                    System.out.println(new String(encryptedMessage));
                    Message decryptedMessage = null;

                    if (clientEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                        byte[] decryptedBytes = asymmetricEncryption.decryptMessage(encryptedMessage);
                        decryptedMessage = Message.fromBytes(decryptedBytes);
                    } else if (clientEncryption instanceof SymmetricEncryption symmetricEncryption) {
                        byte[] decryptedBytes = symmetricEncryption.do_SymDecryption(encryptedMessage, clientDiffieHellmanPrivateSharedKey);
                        decryptedMessage = Message.fromBytes(decryptedBytes);
                    }
                    System.out.println("Decrypted message bytes: ");
                    System.out.println(new String(decryptedMessage.toBytes()));


                    if (decryptedMessage.messageType().equals(MessageType.AsymmetricPublicKey)) {
                        serverAsymmetricPublicKey = decryptedMessage.publicKey();
                        System.out.println("Received public key from the server.");
                    } else if (decryptedMessage.messageType().equals(MessageType.Error)) {
                        System.out.println("Server already has a client with that username.");
                        closeConnection();
                        exit(1);
                    } else {
                        System.out.println(decryptedMessage.username() + ": " + decryptedMessage.message());
                    }


                } catch (Exception e) {
                    e.printStackTrace();
                    try {
                        closeConnection();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                    break;
                }
            }

        }).start();
    }

    /**
     * Closes this client's connection.
     *
     * @throws IOException
     */
    private void closeConnection() throws IOException {
        clientSocket.close();
        outputStream.close();
        inputStream.close();
        System.out.println("Connection closed.");
        exit(1);
    }

}
