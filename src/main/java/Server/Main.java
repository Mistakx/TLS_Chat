package Server;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {

        ClientsAcceptor clientsAcceptor = new ClientsAcceptor(8000);

        Thread serverThread = new Thread(clientsAcceptor);
        serverThread.start();
        System.out.println("Server started.");


    }

}
