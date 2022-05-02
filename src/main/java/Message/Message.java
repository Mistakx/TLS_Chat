package Message;

import java.io.*;
import java.security.PublicKey;

// TODO: Implement message hash
public record Message(
        MessageType messageType,
        String username,
        String message,
        String messageHash,
        PublicKey publicKey
) implements Serializable {

    public byte[] toBytes() throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

        objectOutputStream.writeObject(this);
        objectOutputStream.flush();
        byte[] recordBytes = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return recordBytes;
    }

    public static Message fromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
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
