package Client;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {

        Scanner inputScanner = new Scanner(System.in);
        System.out.println("Write your username: ");
        String userName = inputScanner.nextLine();
        System.out.println("Chosen username: " + userName);
        Client client = new Client("127.0.0.1", 8000, userName);
        client.readMessages();
        client.sendMessages();

    }

}
