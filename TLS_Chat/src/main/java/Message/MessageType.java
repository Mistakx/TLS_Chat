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
    AsymmetricPublicKey {
        @Override
        public String toString() {
            return "AsymmetricPublicKey";
        }
    },
    DiffieHellmanPublicKey {
        @Override
        public String toString() {
            return "DiffieHellmanPublicKey";
        }
    }
}
