package Message;

import java.io.Serializable;

public record Message (
        MessageType messageType,
        String username,
        String message
) implements Serializable {
}
