package Client;

import Encryption.Algorithms.AES;
import Encryption.Algorithms.EncryptionAlgorithm;
import Encryption.Algorithms.RSA;
import Encryption.Encryption;
import Encryption.Handshake;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Scanner;

import Encryption.AsymmetricEncryption;

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

    private String userName;

    /**
     * The chosen encryption functions.
     */
    private Encryption encryption;
    private String encryptionAlgorithmType;
    private String encryptionAlgorithmName;
    private int encryptionKeySize;

    private void optionsMenu() {
        EncryptionAlgorithm encryptionAlgorithm = new RSA();
        encryptionAlgorithmType = encryptionAlgorithm.getType();
        encryptionAlgorithmName = encryptionAlgorithm.getName();
        encryptionKeySize = encryptionAlgorithm.getKeySizes().get(0);
        this.encryption = new AsymmetricEncryption(encryptionAlgorithmName, encryptionKeySize);
    }

    private void startServerHandshake() throws IOException {

        if (encryptionAlgorithmName == null) {
            System.out.println("Encryption algorithm not chosen yet.");
            return;
        } else if (encryptionKeySize == 0) {
            System.out.println("Encryption algorithm size not chosen yet.");
            return;
        }

        Handshake handshake = null;
        if (encryption instanceof AsymmetricEncryption) {
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) encryption;
            PublicKey publicKey = asymmetricEncryption.getPublicKey();
            handshake = new Handshake(userName, "Asymmetric", encryption.getAlgorithmName(), encryption.getAlgorithmKeySize(), publicKey);
        } else {
            handshake = new Handshake(userName, "Symmetric", encryption.getAlgorithmName(), encryption.getAlgorithmKeySize(), null);
        }
        try {
            outputStream.writeObject(handshake);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void changeUsername() {
        Scanner inputScanner = new Scanner(System.in);
        System.out.println("Enter new username: ");
        userName = inputScanner.nextLine();
    }

    public Client(String host, int port) throws IOException {

        clientSocket = new Socket(host, port);
        outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        inputStream = new ObjectInputStream(clientSocket.getInputStream());

        changeUsername();
        optionsMenu();
        System.out.println("Started server handshake.");
        startServerHandshake();
        System.out.println("Ended server handshake.");

    }


    public void sendMessages() throws IOException {
        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.println(userName + ": ");
            String message = inputScanner.nextLine();
            try {
                outputStream.writeObject(message);
            } catch (IOException e) {
                closeConnection();
                break;
            }
        }

    }

    public void readMessages() {
        new Thread(() -> {
            while (clientSocket.isConnected()) {
                try {
                    ArrayList<Object> messageWithUserName = (ArrayList<Object>) inputStream.readObject();
                    String userName = (String) messageWithUserName.get(0);
                    String messageDecrypted = new String((byte[]) messageWithUserName.get(1));
                    System.out.println(userName + ": " + messageDecrypted);
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

    private void closeConnection() throws IOException {
        clientSocket.close();
        outputStream.close();
        inputStream.close();
    }

}
