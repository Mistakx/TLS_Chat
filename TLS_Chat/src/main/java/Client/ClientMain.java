package Client;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ClientMain {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException {

        Client client = new Client("127.0.0.1", 8001);
        try {


            client.readMessages();
            try {
                client.sendMessages();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            System.out.println("Error occurred while connecting to the server.");
            e.printStackTrace();
        }

    }

}
