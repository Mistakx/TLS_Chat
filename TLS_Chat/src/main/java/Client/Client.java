package Client;

import Encryption.Algorithms.*;
import Encryption.AsymmetricEncryption;
import Encryption.DiffieHellman;
import Encryption.Encryption;
import Encryption.SymmetricEncryption;
import Hashing.Algorithms.HashingAlgorithm;
import Hashing.Algorithms.MD5;
import Hashing.Algorithms.SHA256;
import Hashing.Algorithms.SHA512;
import Hashing.Hash;
import Hashing.Hashing;
import Message.Handshake;
import Message.Message;
import Message.MessageType;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

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
     * The chosen encryption functions.
     */
    private Hashing clientHashing;
    /**
     * The client's handshake information.
     */
    private Handshake clientHandshake = new Handshake(null, null, null, null, null, null, null);
    private PublicKey serverAsymmetricPublicKey;
    private byte[] clientDiffieHellmanPrivateSharedKey;
    /**
     * The chosen encryption algorithm.
     */
    private EncryptionAlgorithm chosenEncryptionAlgorithm;
    /**
     * The chosen encryption algorithm's key size.
     */
    private int keySize;
    /**
     * The chosen hash algorithm.
     */
    private HashingAlgorithm chosenHashAlgorithm;
    /**
     * The chosen hash algorithm's block size.
     */
    private int blockSize;

    /**
     * The settings menu to change the client's settings.
     */
    private void optionsMenu() {
        Scanner usrInput = new Scanner(System.in);
        System.out.println("--------------------------------------------------------\n Please select the encryption algorithm you want to use: \n * 1- AES \n * 2- DES \n * 3- 3DES \n * 4- RSA");
        int op1 = usrInput.nextInt();
        switch (op1) {
            case 1 -> {
                chosenEncryptionAlgorithm = new AES();
                System.out.println("----------------------------\n Please select the key size: \n * 1- 128bits \n * 2- 192bits \n * 3- 256bits");
                System.out.print("Your option: ");
                int op2 = usrInput.nextInt();
                keySize = chosenEncryptionAlgorithm.getKeySizes().get(op2 - 1);
            }
            case 2 -> {
                chosenEncryptionAlgorithm = new DES();
                keySize = chosenEncryptionAlgorithm.getKeySizes().get(0);
            }
            case 3 -> {
                chosenEncryptionAlgorithm = new DES3();
                keySize = chosenEncryptionAlgorithm.getKeySizes().get(0);
            }
            case 4 -> {
                chosenEncryptionAlgorithm = new RSA();
                System.out.println("---------------------------------------\n Please select the key size: \n * 1- 512bits \n * 2- 1024bits \n * 3- 2048bits");
                System.out.print("Your option: ");
                int op3 = usrInput.nextInt();
                keySize = chosenEncryptionAlgorithm.getKeySizes().get(op3 - 1);
            }
            default -> {
                System.out.print("Invalid option, restarting setup....\n");
                optionsMenu();
            }
        }
        System.out.println("--------------------------------------------------\n Please select the hash algorithm you want to use: \n * 1- MD5 \n * 2- SHA-256 \n * 3- SHA-512");
        int op4 = usrInput.nextInt();
        switch (op4) {
            case 1 -> {
                chosenHashAlgorithm = new MD5();
                blockSize = chosenHashAlgorithm.getBlockSize().get(0);
            }
            case 2 -> {
                chosenHashAlgorithm = new SHA256();
                blockSize = chosenHashAlgorithm.getBlockSize().get(0);
            }
            case 3 -> {
                chosenHashAlgorithm = new SHA512();
                blockSize = chosenHashAlgorithm.getBlockSize().get(0);
            }
            default -> {
                System.out.print("Invalid option, restarting setup....\n");
                optionsMenu();
            }
        }

        clientHandshake = new Handshake(clientHandshake.username(), chosenEncryptionAlgorithm.getType(), chosenEncryptionAlgorithm.getName(), keySize, clientHandshake.publicKey(), chosenHashAlgorithm.getName(), blockSize);
        clientHashing = new Hash(clientHandshake.hashAlgorithmName(), clientHandshake.blockSize());
        if (clientHandshake.encryptionAlgorithmType().equals("Symmetric")) {
            clientEncryption = new SymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            clientHandshake = new Handshake(clientHandshake.username(), clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey(), clientHandshake.hashAlgorithmName(), clientHandshake.blockSize());
        } else if (clientHandshake.encryptionAlgorithmType().equals("Asymmetric")) {
            clientEncryption = new AsymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) clientEncryption;
            clientHandshake = new Handshake(clientHandshake.username(), clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), asymmetricEncryption.getPublicKey(), clientHandshake.hashAlgorithmName(), clientHandshake.blockSize());
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
            handshake = new Handshake(clientHandshake.username(), "Asymmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), publicKey, clientHashing.getAlgorithmName(), clientHashing.getBlockSize());
            outputStream.writeObject(handshake);
            // The server's public key is sent to the client already encrypted.
        } else if (clientEncryption instanceof SymmetricEncryption) {
            System.out.println("Started symmetric encryption handshake.");
            DiffieHellman diffieHellman = new DiffieHellman();
            PrivateKey privateKey = diffieHellman.generatePrivateKey();
            PublicKey publicKey = diffieHellman.generatePublicKey();
            handshake = new Handshake(clientHandshake.username(), "Symmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), publicKey, clientHashing.getAlgorithmName(), clientHashing.getBlockSize());
            outputStream.writeObject(handshake);
            outputStream.flush();
            PublicKey clientPublicKey = (PublicKey) inputStream.readObject();
            clientDiffieHellmanPrivateSharedKey = diffieHellman.computePrivateKey(clientPublicKey, clientHandshake.encryptionKeySize());
            System.out.println("Server and client agreed on private key: ");
            System.out.println(new BigInteger(clientDiffieHellmanPrivateSharedKey));
        }

    }

    /**
     * Sets the username for the client
     */
    private void changeUsername() {
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Enter new username: ");
        String newUsername = inputScanner.nextLine();
        clientHandshake = new Handshake(newUsername, clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey(), clientHandshake.encryptionAlgorithmName(), clientHandshake.blockSize());
    }

    /**
     * Constructor
     *
     * @param host Host Ip
     * @param port port of the connection
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws ClassNotFoundException
     * @throws InvalidKeyException
     */
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
            Thread.sleep(300);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.println("\n" + clientHandshake.username() + ": ");
            String messageText = inputScanner.nextLine();

            Hash msgHash = new Hash(clientHashing.getAlgorithmName(), clientHashing.getBlockSize());
            String hash = msgHash.applyHash(messageText);
            System.out.println("Message Hash:" + hash);
            Message message = new Message(MessageType.Message, clientHandshake.username(), messageText, hash, null);

            byte[] messageBytes = message.toBytes();
            byte[] encryptedMessage = new byte[0];

            if (clientEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                encryptedMessage = asymmetricEncryption.encryptMessage(messageBytes, serverAsymmetricPublicKey);
            } else if (clientEncryption instanceof SymmetricEncryption symmetricEncryption) {
                encryptedMessage = symmetricEncryption.do_SymEncryption(messageBytes, clientDiffieHellmanPrivateSharedKey);
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

                    if (decryptedMessage.message() != null) {
                        Hash msgHash = new Hash(clientHashing.getAlgorithmName(), clientHashing.getBlockSize());
                        String hashReceived = msgHash.applyHash(decryptedMessage.message());
                        System.out.println("Hash received: " + hashReceived);
                        System.out.println("Message hash: " + decryptedMessage.messageHash());

                        if (decryptedMessage.messageHash().equals(hashReceived)) {
                            System.out.println("VALID MESSAGE!");
                        } else {
                            System.out.println("THE MESSAGE HAS BEEN ALTERED!!");
                        }
                    }

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
