package Server;

import Encryption.Encryption;
import Message.Handshake;
import Message.Message;
import Message.MessageType;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import Encryption.AsymmetricEncryption;

public class ClientHandler implements Runnable {

    public static final List<ClientHandler> clientHandlers = Collections.synchronizedList(new ArrayList<>());

    private final ObjectInputStream inputStream;
    private final ObjectOutputStream outputStream;
    private final Socket clientSocket;

    /**
     * The client's handshake made when the client connects to the server.
     */
    private Handshake clientHandshake;
    /**
     * The chosen encryption functions.
     */
    private Encryption encryption;


    private static boolean clientAlreadyExists(String clientUsername) {

        for (ClientHandler currentClientHandler : clientHandlers) {
            if (currentClientHandler.getUsername().equals(clientUsername)) {
                return true;
            }
        }
        return false;
    }

    public ClientHandler(Socket clientSocket) throws IOException, ClassNotFoundException {

        this.clientSocket = clientSocket;
        this.inputStream = new ObjectInputStream(clientSocket.getInputStream());
        this.outputStream = new ObjectOutputStream(clientSocket.getOutputStream());

    }

    /**
     * Initializes the encryption according to the server's handshake.
     */
    private void initializeEncryption(Handshake handshake) {

        if (handshake.encryptionAlgorithmType().equals("Symmetric")) {
            // TODO: Implement symmetric encryption.
        }

        else if (handshake.encryptionAlgorithmType().equals("Asymmetric")) {
            encryption = new AsymmetricEncryption(handshake.encryptionAlgorithmName(), handshake.encryptionKeySize());
        }

    }

    /**
     * Starts
     *
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private void startServerHandshake() throws IOException, ClassNotFoundException {

        System.out.println("Started handshake with the client.");
        clientHandshake = (Handshake) inputStream.readObject();
        System.out.println("Ended handshake with the client.");

        if (clientAlreadyExists(clientHandshake.username())) {
            System.out.println("Server already has a client with that username.");
            Message errorMessage = new Message(MessageType.Error, "Server", "Server already has a client with that username.");
            this.outputStream.writeObject(errorMessage);
            this.outputStream.flush();
            return;
        }

        if (clientHandshake.publicKey() != null) {
            System.out.println("Received public key from the client.");
        } else {
            System.out.println("Didn't receive public key from the client (Client is using symmetric encryption).");
        }

        clientHandlers.add(this);
        System.out.println(this.getUsername() + " has joined the server.\n");
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


        while (clientSocket.isConnected()) {
            try {
                Message message = (Message) inputStream.readObject();
                broadcastMessage(message);
            } catch (IOException | ClassNotFoundException e) {
                try {
                    removeClient(this);
                    break;
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                e.printStackTrace();
            }
        }
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
        inputStream.close();
        outputStream.close();
    }

    /**
     * Sends a message to all other clients.
     *
     * @param message The message to be sent.
     * @throws IOException
     */
    public void broadcastMessage(Message message) throws IOException {
        for (ClientHandler currentClient : clientHandlers) {
            if (!this.equals(currentClient)) {
                currentClient.outputStream.writeObject(message);
                currentClient.outputStream.flush();
            }
        }
    }

    /**
     * Sends a message to a specific client.
     * @param message The message to be sent.
     * @param clientUsername The client to send the message to.
     * @throws IOException
     */
    public void sendMessageToClient(Message message, String clientUsername) throws IOException {
        for (ClientHandler currentClient : clientHandlers) {
            if (currentClient.getUsername().equals(clientUsername)) {
                currentClient.outputStream.writeObject(message);
                currentClient.outputStream.flush();

            }
        }
    }

    /**
     * @return The client's username.
     */
    public String getUsername() {
        return clientHandshake.username();
    }
}
