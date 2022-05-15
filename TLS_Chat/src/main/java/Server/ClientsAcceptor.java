package Server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Class responsible for continuously accepting clients, and start their respective handler.
 */
public class ClientsAcceptor implements Runnable {

    private final ServerSocket server;

    /**
     * Constructor
     *
     * @param port port of the connection
     * @throws IOException
     */
    public ClientsAcceptor(int port) throws IOException {
        server = new ServerSocket(port);
    }

    @Override
    public void run() {

        try {
            while (!server.isClosed()) {
                Socket clientSocket = server.accept();
                System.out.println("\nClient accepted.");
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread clientHandlerThread = new Thread(clientHandler);
                clientHandlerThread.start();
                System.out.println("Started thread to handle the accepted client.\n");
            }
        } catch (IOException | ClassNotFoundException e) {
            try {
                closeConnection();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

    }

    /**
     * Closes the connection
     *
     * @throws IOException
     */
    private void closeConnection() throws IOException {
        server.close();
    }

}