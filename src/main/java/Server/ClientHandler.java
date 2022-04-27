package Server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class ClientHandler implements Runnable {

    public static final ArrayList<ClientHandler> clientHandlers = new ArrayList<>();
    private final ObjectInputStream inputStream;
    private final ObjectOutputStream outputStream;
    private final String userName;
    private final Socket server;

    public ClientHandler(Socket server) throws IOException, ClassNotFoundException {
        this.server = server;
        this.inputStream = new ObjectInputStream(server.getInputStream());
        this.outputStream = new ObjectOutputStream(server.getOutputStream());
        this.userName = (String) inputStream.readObject();
        System.out.println(this.userName + " has joined the server.");
        clientHandlers.add(this);
    }

    @Override
    public void run() {

        while (server.isConnected()) {
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
        server.close();
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
