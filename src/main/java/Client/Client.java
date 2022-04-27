package Client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

public class Client {

    private final Socket clientSocket;
    private final ObjectInputStream inputStream;
    private final ObjectOutputStream outputStream;
    private final String userName;

    public Client(String host, int port, String userName) throws IOException {
        clientSocket = new Socket(host, port);
        this.userName = userName;
        outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        inputStream = new ObjectInputStream(clientSocket.getInputStream());
        outputStream.writeObject(userName);
    }

    public void sendMessages() throws IOException {
        while (clientSocket.isConnected()) {
            Scanner inputScanner = new Scanner(System.in);
            System.out.println("Message: ");
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
