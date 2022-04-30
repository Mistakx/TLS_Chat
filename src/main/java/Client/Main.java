package Client;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    private static String encAlgorithm;
    private static String userName;
    private static String hashAlg;
    private static String EncryptionType;
    private static int    keySize;


    /**
     * This function reads the user option and saves the encryption algorithm selected.
     * Depending on the algorithm selected this function can ask the user for the key size to be used.
     *
     * @param option represents the option the user selected as for what encryption algorithm to use.
     */
    private static void getEncAlg( int option ){
        Scanner usrInput = new Scanner( System.in );
        switch ( option ) {
            case 1 -> {
                encAlgorithm = "AES";
                System.out.println( "---------------------------------------\n Please select the key size: \n * 1- 128bits \n * 2- 192bits \n * 3- 256bits" );
                int op1 = usrInput.nextInt( );
                switch ( op1 ) {
                    case 1 -> keySize = 128;
                    case 2 -> keySize = 192;
                    case 3 -> keySize = 256;
                }
            }
            case 2 -> {
                encAlgorithm = "DES";
                keySize = 56;  //56 relevant bits?
            }
            case 3 -> {
                encAlgorithm = "3DES";
                keySize = 56;  //56 relevant bits?
            }

        }
    }

    /**
     * This function reads the user option and saves the type of hash function to be used.
     *
     * @param option represents the option the user selected as for what hash function to use.
     */
    private static void getEncryptionType( int option ) {
        switch ( option ) {
            case 1 -> EncryptionType = "Symmetric"; //symmetric encryption
            //create shared secret key (between client and server only)

            case 2 -> EncryptionType = "Asymmetric"; //Encryption with public key
            //The server will use this client's public key to decrypt
        }
    }

    /**
     * This function reads the user option and saves the hash algorithm selected.
     *
     * @param option represents the option the user selected as for what hash algorithm to use.
     */
    private static void getHashAlg( int option ){
        switch ( option ) {
            case 1 -> hashAlg = "SHA-256";
            case 2 -> hashAlg = "SHA-512";
            case 3 -> hashAlg = "MD4";
            case 4 -> hashAlg = "MD5";
        }
    }

    /**
     * This function uses the console to ask the user for the value of various variables in order to create a new client.
     */
    private static void encryptionSettings( ){
        Scanner usrInput = new Scanner( System.in );

        System.out.println( "-------------------------------------------------------\n Please select the Encryption method you want to use: \n * 1- Symmetric encryption \n * 2- Asymmetric encryption" );
        int op1 = usrInput.nextInt( );
        getEncryptionType( op1 );

        if (EncryptionType == "Symmetric") {
            System.out.println("------------------------------------------------------------------\n Please select the Symmetric encryption algorithm you want to use: \n * 1- AES \n * 2- DES \n * 3- 3DES");
            int op2 = usrInput.nextInt();
            getEncAlg(op2);
        }else{
            encAlgorithm = "RSA";
            System.out.println( "---------------------------------------\n Please select the key size: \n * 1- 1024bits \n * 2- 2048bits \n * 3- 4096bits" );
            int op3 = usrInput.nextInt( );
            switch ( op3 ) {
                case 1 -> keySize = 1024;
                case 2 -> keySize = 2048;
                case 3 -> keySize = 4096;
            }
        }

        System.out.println( "-------------------------------------------------\n Please select the hash algorithm you want to use: \n * 1- SHA-256 \n * 2- SHA-512 \n * 3- MD4\n * 4- MD5" );
        int op4 = usrInput.nextInt( );
        getHashAlg( op4 );
    }

    /**
     * This function ask the user for a new username for the client.
     */
    private static void newUsername( ){
        Scanner usrInput = new Scanner( System.in );
        System.out.println( "Enter new username: " );
        userName = usrInput.nextLine( );
    }

    /**
     * This function uses the console to ask the user for the value of various variables in order to create a new client.
     */
    private static void clientSetup( ){
        Scanner usrInput = new Scanner( System.in );
        System.out.println( "Write your username" );
        userName = usrInput.nextLine( );
        System.out.println( "Chosen username: " + userName +"\n" );
        System.out.println( "-------------------------------------\n Do you want to change your username? \n * 1- Change Username \n * 2- No, start setting up encryption settings" );
        int option = usrInput.nextInt( );
        switch ( option ) {
            case 1 -> {
                newUsername( );
                encryptionSettings( );
            }
            case 2 -> encryptionSettings( );
        }
    }


    public static void main(String[] args) throws Exception {

        clientSetup( );
        try {
            Client client = new Client("127.0.0.1", 8000, userName, EncryptionType, encAlgorithm, keySize, hashAlg);
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
