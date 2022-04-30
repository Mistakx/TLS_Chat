package Client;

import java.io.IOException;

public class ClientMain {

    public static void main(String[] args) throws IOException {


        try {
            Client client = new Client("127.0.0.1", 8000);
            client.readMessages();
            try {
                client.sendMessages();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            System.out.println("Error occurred while connecting to the server.");
        }
    }

}
