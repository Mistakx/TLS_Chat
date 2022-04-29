package Server;

import Encryption.Handshake;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ClientHandler implements Runnable {

    public static final List<ClientHandler> clientHandlers = Collections.synchronizedList(new ArrayList<>());
    public static final List<String> userNames = Collections.synchronizedList(new ArrayList<>());
    public static final List<PublicKey> publicKeys = Collections.synchronizedList(new ArrayList<>());

    private final ObjectInputStream inputStream;
    private final ObjectOutputStream outputStream;
    private final Socket clientSocket;

    private final String userName;
    private final String encryptionAlgorithmType;
    private final String encryptionAlgorithmName;
    private final int encryptionKeySize;
    private final PublicKey publicKey;


    public ClientHandler(Socket clientSocket) throws IOException, ClassNotFoundException {

        this.clientSocket = clientSocket;
        this.inputStream = new ObjectInputStream(clientSocket.getInputStream());
        this.outputStream = new ObjectOutputStream(clientSocket.getOutputStream());

        System.out.println("Started handshake with the client.");
        Handshake handshake = (Handshake) inputStream.readObject();
        System.out.println("Ended handshake with the client.");
        this.userName = handshake.userName();
        this.encryptionAlgorithmType = handshake.encryptionAlgorithmType();
        this.encryptionAlgorithmName = handshake.encryptionAlgorithmName();
        this.encryptionKeySize = handshake.encryptionKeySize();
        this.publicKey = handshake.publicKey();

        System.out.println(this.userName + " has joined the server.");
        if (userNames.contains(userName)) {
            outputStream.writeObject("Server already has a client with that username.");
            return;
        }
        userNames.add(userName);

        if (publicKey != null) {
            publicKeys.add(publicKey);
            updateClientPublicKeys();
            System.out.println("Received public key from the client.");
        } else {
            System.out.println("Didn't receive public key from the client (Client is using symmetric encryption).");
        }
        clientHandlers.add(this);
    }

    private void updateClientPublicKeys() throws IOException {
        for (ClientHandler client : clientHandlers) {
            client.outputStream.writeObject("UPDATE_PUBLIC_KEYS");
            client.outputStream.writeObject(publicKeys.size());
            for (int i = 0; i < publicKeys.size(); i++) {
                client.outputStream.writeObject(publicKeys.get(i));
                client.outputStream.writeObject(userNames.get(i));
            }
            client.outputStream.flush();
        }
    }

    @Override
    public void run() {

        while (clientSocket.isConnected()) {
            try {
                String message = (String) inputStream.readObject();
                broadcastMessage(message.getBytes(StandardCharsets.UTF_8));
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

    private void removeClient(ClientHandler client) throws IOException {
        clientHandlers.remove(client);
        clientSocket.close();
        inputStream.close();
        outputStream.close();
    }

    public void broadcastMessage(byte[] message) throws IOException {
        for (ClientHandler client : clientHandlers) {
            if (!this.equals(client)) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    messageWithUserName.add(this.userName);
                    messageWithUserName.add(message);
                    client.outputStream.writeObject(messageWithUserName);
                    client.outputStream.flush();
                } catch (IOException e) {
                    removeClient(client);
                }
            }
        }
    }

    public String getUserName() {
        return userName;
    }
}
