package Message;

public enum MessageType {

    Error {
        @Override
        public String toString() {
            return "Error";
        }
    },
    Message {
        @Override
        public String toString() {
            return "Message";
        }
    },
    PublicKey {
        @Override
        public String toString() {
            return "PublicKey";
        }
    }
}
