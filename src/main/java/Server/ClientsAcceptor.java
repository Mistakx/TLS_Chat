package Server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Class responsible for continuously accepting clients, and start their respective handler.
 */
public class ClientsAcceptor implements Runnable {

    private final ServerSocket server;

    public ClientsAcceptor(int port) throws IOException {
        server = new ServerSocket(port);
    }

    @Override
    public void run() {

        try {
            while (!server.isClosed()) {
                System.out.println("Started accepting clients.");
                Socket clientSocket = server.accept();
                System.out.println("Client accepted.");
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread clientHandlerThread = new Thread(clientHandler);
                clientHandlerThread.start();
                System.out.println(!server.isClosed());
            }
        } catch (IOException | ClassNotFoundException e) {
            try {
                closeConnection();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

    }

    private void closeConnection() throws IOException {
        server.close();
    }

}