package Message;

import java.io.*;
import java.security.PublicKey;

public record Message(
        MessageType messageType,
        String username,
        String message,
        String messageHash,
        PublicKey publicKey
) implements Serializable {

    /**
     * Casts into bytes
     *
     * @return
     * @throws IOException
     */
    public byte[] toBytes() throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

        objectOutputStream.writeObject(this);
        objectOutputStream.flush();
        byte[] recordBytes = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return recordBytes;
    }

    /**
     * Casts the bytes into a message
     *
     * @param bytes to be turned into a message
     * @return
     */
    public static Message fromBytes(byte[] bytes) {
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            Message message = (Message) objectInputStream.readObject();
            return message;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
