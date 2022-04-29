package Client;

import Encryption.Algorithms.EncryptionAlgorithm;
import Encryption.Algorithms.RSA;
import Encryption.Encryption;
import Message.Handshake;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;

import Encryption.AsymmetricEncryption;
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
    private Encryption encryption;

    /**
     * The client's handshake information.
     */
    private Handshake clientHandshake = new Handshake(null,null,null,0,null);

    private void optionsMenu() {
        EncryptionAlgorithm chosenEncryptionAlgorithm = new RSA();
        String chosenEncryptionAlgorithmType = chosenEncryptionAlgorithm.getType();
        String chosenEncryptionAlgorithmName = chosenEncryptionAlgorithm.getName();
        int chosenEncryptionKeySize = chosenEncryptionAlgorithm.getKeySizes().get(0);
        clientHandshake = new Handshake(clientHandshake.username(), chosenEncryptionAlgorithmType, chosenEncryptionAlgorithmName, chosenEncryptionKeySize, clientHandshake.publicKey());

        if (clientHandshake.encryptionAlgorithmType().equals("Symmetric")) {
            // TODO: Implement symmetric encryption.

        } else if (clientHandshake.encryptionAlgorithmType().equals("Asymmetric")) {
            encryption = new AsymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) encryption;
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
        if (encryption instanceof AsymmetricEncryption) {
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) encryption;
            PublicKey publicKey = asymmetricEncryption.getPublicKey();
            handshake = new Handshake(clientHandshake.username(), "Asymmetric", encryption.getAlgorithmName(), encryption.getAlgorithmKeySize(), publicKey);
        } else {
            handshake = new Handshake(clientHandshake.username(), "Symmetric", encryption.getAlgorithmName(), encryption.getAlgorithmKeySize(), null);
        }
        outputStream.writeObject(handshake);
    }

    private void changeUsername() {
        Scanner inputScanner = new Scanner(System.in);
        System.out.println("Enter new username: ");
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
    public void sendMessages() throws IOException {

        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.println(clientHandshake.username() + ": ");
            String messageText = inputScanner.nextLine();
            Message message = new Message(MessageType.Message, clientHandshake.username(), messageText);
            try {
                outputStream.writeObject(message);
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

        new Thread(() -> {

            while (clientSocket.isConnected()) {
                try {

                    Message message = (Message) inputStream.readObject();
                    System.out.println(message.username() + ": " + message.message());
                    if (message.message().equals("Server already has a client with that username.")) {
                        closeConnection();
                        exit(1);
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
    }

}
