package Client;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {


        try {
            Client client = new Client("127.0.0.1", 8000);
            client.readMessages();
            client.sendMessages();
        } catch (IOException e) {
            System.out.println("Error occurred while connecting to the server.");
        }
    }

}
