package Message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
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
        ObjectOutputStream objectOutputStream;

        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(this);
        objectOutputStream.flush();
        byte[] recordBytes = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return recordBytes;
    }

}
