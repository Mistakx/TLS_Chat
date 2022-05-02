package Server;

import Encryption.Encryption;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import Encryption.AsymmetricEncryption;
import Encryption.SymmetricEncryption;
import Encryption.DiffieHellman;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientHandler implements Runnable {

    public static final List<ClientHandler> clientHandlers = Collections.synchronizedList(new ArrayList<>());

    private final ObjectInputStream clientInputStream;
    private final ObjectOutputStream clientOutputStream;
    private final Socket clientSocket;

    /**
     * The client's handshake made when the client connects to the server.
     */
    private Handshake clientHandshake;
    /**
     * The client handler's encryption.
     */
    private Encryption serverEncryption;

    private byte[] serverDiffieHellmanPrivateSharedKey;


    public ClientHandler(Socket clientSocket) throws IOException, ClassNotFoundException {

        this.clientSocket = clientSocket;
        this.clientInputStream = new ObjectInputStream(clientSocket.getInputStream());
        this.clientOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());

    }


    /**
     * Checks if a client with a username is already connected.
     *
     * @param clientUsername The client's username to check.
     */
    private boolean clientAlreadyExists(String clientUsername) {

        for (ClientHandler currentClient : clientHandlers) {
            if (currentClient.clientHandshake.username().equals(clientUsername)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Removes a client from the server.
     *
     * @param client The client to be removed.
     * @throws IOException
     */
    private void removeClient(ClientHandler client) throws IOException {
        clientHandlers.remove(client);
        clientSocket.close();
        clientInputStream.close();
        clientOutputStream.close();
    }


    /**
     * Sends a message to all other clients.
     *
     * @param message The message to be sent.
     * @throws IOException
     */
    public void broadcastEncryptedMessage(Message message) throws Exception {
        for (ClientHandler currentClient : clientHandlers) {
            if (!this.equals(currentClient)) {

                if (currentClient.serverEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                    byte[] encryptedMessage = asymmetricEncryption.encryptMessage(message.toBytes(), currentClient.clientHandshake.publicKey());
                    currentClient.clientOutputStream.writeObject(encryptedMessage);
                    currentClient.clientOutputStream.flush();
                } else if ((currentClient.serverEncryption instanceof SymmetricEncryption symmetricEncryption)) {
                    byte[] encryptedMessage = symmetricEncryption.do_SymEncryption(message.toBytes(), currentClient.serverDiffieHellmanPrivateSharedKey);
                    currentClient.clientOutputStream.writeObject(encryptedMessage);
                    currentClient.clientOutputStream.flush();
                }

            }
        }
    }

    /**
     * Sends a message to a specific client.
     *
     * @param message        The message to be sent.
     * @param clientUsername The client to send the message to.
     * @throws IOException
     */
    public void sendEncryptedMessageToClient(Message message, String clientUsername) throws Exception {
        for (ClientHandler currentClient : clientHandlers) {
            if (currentClient.clientHandshake.username().equals(clientUsername)) {
                if (serverEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                    byte[] encryptedMessage = asymmetricEncryption.encryptMessage(message.toBytes(), clientHandshake.publicKey());
                    currentClient.clientOutputStream.writeObject(encryptedMessage);
                    currentClient.clientOutputStream.flush();
                } else if ((currentClient.serverEncryption instanceof SymmetricEncryption symmetricEncryption)) {
                    byte[] encryptedMessage = symmetricEncryption.do_SymEncryption(message.toBytes(), serverDiffieHellmanPrivateSharedKey);
                    currentClient.clientOutputStream.writeObject(encryptedMessage);
                    currentClient.clientOutputStream.flush();
                }

            }
        }
    }

    /**
     * Sends a message to this specific handler's client.
     *
     * @param message The message to be sent.
     * @throws IOException
     */
    public void sendEncryptedMessageToThisClient(Message message) throws Exception {
        if (serverEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
            byte[] encryptedMessage = asymmetricEncryption.encryptMessage(message.toBytes(), clientHandshake.publicKey());
            clientOutputStream.writeObject(encryptedMessage);
            clientOutputStream.flush();
        } else if ((serverEncryption instanceof SymmetricEncryption symmetricEncryption)) {
            byte[] encryptedMessage = symmetricEncryption.do_SymEncryption(message.toBytes(), serverDiffieHellmanPrivateSharedKey);
            clientOutputStream.writeObject(encryptedMessage);
            clientOutputStream.flush();
        }

    }


    /**
     * Initializes the encryption according to the client's handshake.
     */
    private void initializeEncryption() {

        if (clientHandshake.encryptionAlgorithmType().equals("Symmetric")) {
            serverEncryption = new SymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
        } else if (clientHandshake.encryptionAlgorithmType().equals("Asymmetric")) {
            serverEncryption = new AsymmetricEncryption(clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize());
        }

    }

    /**
     * This function creates a private key shared between the server and the client
     *
     * @param clientOutputStream what is sent to the client
     * @return the shared private key
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     */
    private void agreeOnSharedPrivateKey(ObjectOutputStream clientOutputStream) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        DiffieHellman diffieHellman = new DiffieHellman();
        PrivateKey privateKey = diffieHellman.generatePrivateKey();
        PublicKey publicKey = diffieHellman.generatePublicKey();
        serverDiffieHellmanPrivateSharedKey = diffieHellman.computePrivateKey(clientHandshake.publicKey(), clientHandshake.encryptionKeySize());
        clientOutputStream.writeObject(publicKey);
        clientOutputStream.flush();
    }

    /**
     * Starts the handshake with the client.
     *
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private void startServerHandshake() throws Exception {

        System.out.println("Started handshake with the client.");
        clientHandshake = (Handshake) clientInputStream.readObject();
        System.out.println("Ended handshake with the client.");
        initializeEncryption();
        System.out.println("Set up encryption according to the handshake with the client.");
        System.out.println("Client encryption algorithm: " + clientHandshake.encryptionAlgorithmName());
        System.out.println("Client encryption key size: " + clientHandshake.encryptionKeySize());

        if (serverEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
            System.out.println("Received public key from the client. Sending server's public key to the client.");
            Message message = new Message(MessageType.AsymmetricPublicKey, "Server", null, null, asymmetricEncryption.getPublicKey());
            sendEncryptedMessageToThisClient(message);
        } else if (serverEncryption instanceof SymmetricEncryption symmetricEncryption) {
            System.out.println("Received Diffie-Hellman public key from the client. Sending server's diffie hellman public key to the client.");
            agreeOnSharedPrivateKey(clientOutputStream);
            System.out.println("Server and client agreed on private key : ");
            System.out.println(new BigInteger(serverDiffieHellmanPrivateSharedKey));
        }

        if (clientAlreadyExists(clientHandshake.username())) {
            System.out.println("Server already has a client with that username.");
            Message errorMessage = new Message(MessageType.Error, "Server", "Server already has a client with that username.", null, null);
            sendEncryptedMessageToThisClient(errorMessage);
            return;
        }



        clientHandlers.add(this);

        System.out.println(clientHandshake.username() + " has joined the server.");
    }


    /**
     * Continuously listens for messages from the clients.
     *
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws ClassNotFoundException
     */
    private void listenToClientsMessages() throws Exception {
        while (clientSocket.isConnected()) {

            byte[] encryptedMessage = (byte[]) clientInputStream.readObject();
            System.out.println("\n" + clientHandshake.username() + " - Encrypted message bytes received: ");
            System.out.println(new String(encryptedMessage));
            Message decryptedMessage = null;

            if (serverEncryption instanceof AsymmetricEncryption asymmetricEncryption) {
                decryptedMessage = Message.fromBytes(asymmetricEncryption.decryptMessage(encryptedMessage));
            } else if (serverEncryption instanceof SymmetricEncryption symmetricEncryption) {
                byte[] decryptedMessageBytes = symmetricEncryption.do_SymDecryption(encryptedMessage, serverDiffieHellmanPrivateSharedKey);
                decryptedMessage = Message.fromBytes(decryptedMessageBytes);
            }
            System.out.println(clientHandshake.username() + " - Decrypted message bytes: ");
            System.out.println(new String(decryptedMessage.toBytes()));
            System.out.println(clientHandshake.username() + ": " + decryptedMessage.message());

            // TODO: Message specific client
            broadcastEncryptedMessage(decryptedMessage);
        }
    }

    @Override
    public void run() {

        // Start the client handshake with the server.
        try {
            startServerHandshake();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // Listen to the clients messages.
        try {
            listenToClientsMessages();
        } catch (Exception e) {
            System.out.println(clientHandshake.username() + " has disconnected.");
            try {
                removeClient(this);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }


    }

}
