package com.encryptioncompat;

class EncryptionException extends RuntimeException {
    EncryptionException(String message) {
        super(message);
    }

    EncryptionException(Throwable cause) {
        super(cause.getMessage(), cause);
    }
}
