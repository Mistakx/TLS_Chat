package Server;

import java.io.IOException;

public class Main {

    public static void main ( String[] args ) throws IOException {

        Server server = new Server( 8000 );

        Thread serverThread = new Thread( server );
        serverThread.start( );
        System.out.println("Server started.");


    }

}
