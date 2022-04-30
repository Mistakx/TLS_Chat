package Client;

import Encryption.Algorithms.EncryptionAlgorithm;
import Encryption.Algorithms.RSA;
import Encryption.Encryption;
import Message.Handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Scanner;

import Encryption.AsymmetricEncryption;
import Message.Message;
import Message.MessageType;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
    private Handshake clientHandshake = new Handshake(null, null, null, 0, null);

    private PublicKey serverPublicKey;

    private void optionsMenu() {
        EncryptionAlgorithm chosenEncryptionAlgorithm = new RSA();
        String chosenEncryptionAlgorithmType = chosenEncryptionAlgorithm.getType();
        String chosenEncryptionAlgorithmName = chosenEncryptionAlgorithm.getName();
        int chosenEncryptionKeySize = chosenEncryptionAlgorithm.getKeySizes().get(2);
        clientHandshake = new Handshake(clientHandshake.username(), chosenEncryptionAlgorithmType, chosenEncryptionAlgorithmName, chosenEncryptionKeySize, clientHandshake.publicKey());

        if (clientHandshake.encryptionAlgorithmType().equals("Symmetric")) {
            // TODO: Implement symmetric encryption.

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
    private void startServerHandshake() throws IOException {

        if (clientHandshake.encryptionAlgorithmName() == null) {
            System.out.println("Encryption algorithm not chosen yet.");
            return;
        } else if (clientHandshake.encryptionKeySize() == 0) {
            System.out.println("Encryption algorithm size not chosen yet.");
            return;
        }

        Handshake handshake;
        if (clientEncryption instanceof AsymmetricEncryption) {
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) clientEncryption;
            PublicKey publicKey = asymmetricEncryption.getPublicKey();
            handshake = new Handshake(clientHandshake.username(), "Asymmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), publicKey);
        } else {
            handshake = new Handshake(clientHandshake.username(), "Symmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), null);
        }
        outputStream.writeObject(handshake);
    }

    private void changeUsername() {
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Enter new username: ");
        String newUsername = inputScanner.nextLine();
        clientHandshake = new Handshake(newUsername, clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey());
    }

    public Client(String host, int port) throws IOException {

        clientSocket = new Socket(host, port);
        outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        inputStream = new ObjectInputStream(clientSocket.getInputStream());

        changeUsername();
        optionsMenu();
        System.out.println("\nStarted server handshake.");
        startServerHandshake();
        System.out.println("Ended server handshake.\n");

    }

    /**
     * Continuously accept user input and send it to the server.
     *
     * @throws IOException
     */
    public void sendMessages() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.println(clientHandshake.username() + ": ");
            String messageText = inputScanner.nextLine();
            Message message = new Message(MessageType.Message, clientHandshake.username(), messageText, null, null);
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) clientEncryption;
            byte[] messageBytes = message.toBytes();
            byte[] encryptedMessage = asymmetricEncryption.encryptMessage(messageBytes, serverPublicKey);

            try {
                System.out.println("\nDecrypted message: " + new String(messageBytes));
                System.out.println("Encrypted message sent: " + new String(encryptedMessage) + "\n");
                outputStream.writeObject(encryptedMessage);
            } catch (IOException e) {
                closeConnection();
                break;
            }
        }

    }

    /**
     * Continuously read the messages sent to this client's socket.
     */
    public void readMessages() {

        // Waits for the client to get the server's public key
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        new Thread(() -> {

            while (clientSocket.isConnected()) {
                try {

                    Message message = (Message) inputStream.readObject();

                    if (message.messageType().equals(MessageType.PublicKey)) {
                        serverPublicKey = (PublicKey) message.publicKey();
                        System.out.println("Received public key from the server.");
                    } else if (message.messageType().equals(MessageType.Error)) {
                        System.out.println("Server already has a client with that username.");
                        closeConnection();
                        exit(1);
                    } else {
                        System.out.print(message.username() + ": " + message.message());
                    }


                } catch (IOException | ClassNotFoundException e) {
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
