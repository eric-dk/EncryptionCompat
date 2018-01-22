package com.encryptioncompat;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR2;
import static android.util.Base64.DEFAULT;
import static javax.crypto.Cipher.SECRET_KEY;
import static javax.crypto.Cipher.UNWRAP_MODE;
import static javax.crypto.Cipher.WRAP_MODE;

@RequiresApi(JELLY_BEAN_MR2)
final class EncryptionApi18Impl extends EncryptionBaseImpl {
    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String MASTER_KEY   = EncryptionApi18Impl.class.getSimpleName();

    private static volatile EncryptionApi18Impl singleton;

    private final Cipher cipher;
    private final KeyPair keyPair;

    private EncryptionApi18Impl(Context context) {
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            keyPair = getKeyPair(context);
        } catch (GeneralSecurityException | IOException e) {
            throw new EncryptionException(e);
        }
    }

    private KeyPair getKeyPair(Context context) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEY_PROVIDER);
        keyStore.load(null);

        Certificate publicCert = keyStore.getCertificate(MASTER_KEY);
        Key privateKey = keyStore.getKey(MASTER_KEY, null);

        if (publicCert == null || !(privateKey instanceof PrivateKey)) {
            Calendar startTime = Calendar.getInstance();
            Calendar endTime = Calendar.getInstance();
            endTime.add(Calendar.YEAR, 20);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", KEY_PROVIDER);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(MASTER_KEY)
                    .setSerialNumber(BigInteger.ONE)
                    .setSubject(new X500Principal("CN=" + MASTER_KEY + " CA Certificate"))
                    .setStartDate(startTime.getTime())
                    .setEndDate(endTime.getTime())
                    .build();

            generator.initialize(spec);
            return generator.generateKeyPair();
        } else {
            return new KeyPair(publicCert.getPublicKey(), (PrivateKey)privateKey);
        }
    }

    static EncryptionApi18Impl get(Context context) {
        EncryptionApi18Impl instance = singleton;
        if (instance == null) {
            synchronized (EncryptionApi14Impl.class) {
                instance = singleton;
                if (instance == null) {
                    singleton = instance = new EncryptionApi18Impl(context);
                }
            }
        }
        return instance;
    }

    String encrypt(String data) {
        byte[] wrappedKey;
        Key key;
        try {
            key = KeyGenerator.getInstance(KEY_ALGORITHM).generateKey();
            cipher.init(WRAP_MODE, keyPair.getPublic());
            wrappedKey = cipher.wrap(key);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }

        String keyString = Base64.encodeToString(wrappedKey, DEFAULT);
        String result = encrypt(key, data.getBytes());
        return keyString + FIELD_SEPARATOR + result;
    }

    String decrypt(String data) {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 3) {
            throw new EncryptionException("Invalid format");
        }

        byte[] keyText = Base64.decode(fields[0], DEFAULT);
        byte[] iv = Base64.decode(fields[1], DEFAULT);
        byte[] cipherText = Base64.decode(fields[2], DEFAULT);

        Key key;
        try {
            cipher.init(UNWRAP_MODE, keyPair.getPrivate());
            key = cipher.unwrap(keyText, KEY_ALGORITHM, SECRET_KEY);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return decrypt(key, iv, cipherText);
    }
}
