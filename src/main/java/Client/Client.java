package Client;

import Encryption.AsymmetricEncryption;
import Encryption.DiffieHellman;
import Encryption.Encryption;
import Encryption.SymmetricEncryption;
import Message.Handshake;
import Message.Message;
import Message.MessageType;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
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
     * The client's handshake information.
     */
    private Handshake clientHandshake;

    private PublicKey serverPublicKey;

    private BigInteger privateSharedKey;

    /**
     * The settings menu to change the client's settings.
     */
    private void optionsMenu() {

        if (clientHandshake.encryptionAlgorithmType().equals("Symmetric")) {
            clientEncryption = new SymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            clientHandshake = new Handshake(clientHandshake.username(), clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), null, clientHandshake.privateSharedKey());

        } else if (clientHandshake.encryptionAlgorithmType().equals("Asymmetric")) {
            clientEncryption = new AsymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
            AsymmetricEncryption asymmetricEncryption = (AsymmetricEncryption) clientEncryption;
            clientHandshake = new Handshake(clientHandshake.username(), clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), asymmetricEncryption.getPublicKey(), null);
        }
    }

    /**
     * Sends this client's username and chosen encryption information to the server.
     *
     * @throws IOException
     */
    private void startServerHandshake() throws IOException, NoSuchAlgorithmException, ClassNotFoundException {

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
            handshake = new Handshake(clientHandshake.username(), "Asymmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), publicKey, null);
            outputStream.writeObject(handshake);
        } else {
            handshake = new Handshake(clientHandshake.username(), "Symmetric", clientEncryption.getAlgorithmName(), clientEncryption.getAlgorithmKeySize(), null, privateSharedKey);
            outputStream.writeObject(handshake);
            this.privateSharedKey = agreeOnSharedPrivateKey( );
        }
    }

    public Client(String host, int port, String username,String encryptionType,  String encryptionAlgorithm, int encryptionKeySize, String hashAlgorithm ) throws Exception {

        clientSocket = new Socket(host, port);
        outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        inputStream = new ObjectInputStream(clientSocket.getInputStream());

        clientHandshake = new Handshake(username, encryptionType, encryptionAlgorithm, encryptionKeySize, null, null);
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
    public void sendMessages() throws Exception {

        // Waits for the client to get the server's public key
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.print(clientHandshake.username() + ": ");
            String messageText = inputScanner.nextLine();
            Message message = new Message(MessageType.Message, clientHandshake.username(), messageText, null, null);
            byte[] messageBytes = message.toBytes();
            if (clientEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                byte[] encryptedMessage = asymmetricEncryption.encryptMessage(messageBytes, asymmetricEncryption.getPublicKey());
                try {
                    System.out.println("\nDecrypted message: " + new String(messageBytes));
                    System.out.println("Encrypted message sent: " + new String(encryptedMessage) + "\n");
                    outputStream.writeObject(encryptedMessage);
                } catch (IOException e) {
                    closeConnection();
                    break;
                }
            }else if( clientEncryption instanceof SymmetricEncryption symmetricEncryption ){
                byte[] encryptedMessage = symmetricEncryption.do_SymEncryption(messageBytes, this.privateSharedKey.toByteArray());
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

    }

    /**
     * This function creates a private key shared between the client and the server
     * @return shared private key
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     */
    private BigInteger agreeOnSharedPrivateKey ( ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        BigInteger privateKey = DiffieHellman.generatePrivateKey( clientHandshake.encryptionKeySize( ) );
        BigInteger publicKey = DiffieHellman.generatePublicKey( privateKey );
        sendPublicKey( outputStream , publicKey );
        BigInteger clientPublicKey = (BigInteger) inputStream.readObject( );
        return DiffieHellman.computePrivateKey( clientPublicKey , privateKey );
    }

    /**
     * Sends the client's public key to the server
     * @param outputStream is the socket where the key is sent
     * @param publicKey    this client's public key
     * @throws IOException
     */
    private void sendPublicKey ( ObjectOutputStream outputStream , BigInteger publicKey ) throws IOException {
        outputStream.writeObject( publicKey );
        outputStream.flush( );
    }

    /**
     * Continuously read the messages sent to this client's socket.
     */
    public void readMessages() {

        new Thread(() -> {

            while (clientSocket.isConnected()) {
                try {

                    byte[] encryptedMessage = (byte[]) inputStream.readObject();
                    System.out.println("\nReceived encrypted message: ");
                    System.out.println(new String(encryptedMessage));
                    Message decryptedMessage = null;

                    if (clientEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                        decryptedMessage = Message.fromBytes(asymmetricEncryption.decryptMessage(encryptedMessage));
                        System.out.println("Decrypted message: ");
                        System.out.println(new String(decryptedMessage.toBytes()));
                    } else if(clientEncryption instanceof SymmetricEncryption symmetricEncryption){
                        decryptedMessage = Message.fromBytes(symmetricEncryption.do_SymDecryption(encryptedMessage, this.privateSharedKey.toByteArray()));
                        System.out.println("Decrypted message: ");
                        System.out.println(new String(decryptedMessage.toBytes()));
                    }


                    if (decryptedMessage.messageType().equals(MessageType.PublicKey)) {
                        serverPublicKey = decryptedMessage.publicKey();
                        System.out.println("Received public key from the server.");
                    } else if (decryptedMessage.messageType().equals(MessageType.Error)) {
                        System.out.println("Server already has a client with that username.");
                        closeConnection();
                        exit(1);
                    } else {
                        System.out.print(decryptedMessage.username() + ": " + decryptedMessage.message());
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
