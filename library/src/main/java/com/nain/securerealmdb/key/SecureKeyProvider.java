package com.nain.securerealmdb.key;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

/**
 * This Class provides secure key
 * The secure key will be stored in android shared preferences with encryption
 *
 * @author julkar nain
 * @since 3/25/19
 */
public class SecureKeyProvider {

    private static final String PREFERENCES_KEY = "secure_preferences";
    private KeystoreKeyProvider encryptionProvider;
    private Context context;

    public SecureKeyProvider(Context context) {
        this.context = context;
        encryptionProvider = new KeystoreKeyProvider(context);
    }

    public SecureKeyProvider(Context context, String alias) {
        this.context = context;
        encryptionProvider = new KeystoreKeyProvider(context, alias);
    }

    /**
     * This method provide secure encryption key
     *
     * @param keySize        (bit)
     * @param preferencesKey
     * @return key
     */
    public byte[] getSecureKey(int keySize, String preferencesKey) {
        String key = getSharedPreference().getString(preferencesKey, null);

        if (TextUtils.isEmpty(key)) {
            return createSecureKey(keySize, preferencesKey);
        }

        return encryptionProvider.decrypt(key);
    }

    private void saveSecureKey(byte[] key, String preferencesKey) {
        SharedPreferences.Editor editor = getSharedPreference().edit();
        editor.putString(preferencesKey, encryptionProvider.encrypt(key));
        editor.apply();
    }

    private byte[] createSecureKey(int keySize, String preferencesKey) {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGenerator.init(keySize, new SecureRandom());
        byte[] key = keyGenerator.generateKey().getEncoded();
        byte[] key2 = keyGenerator.generateKey().getEncoded();

        byte[] combined = new byte[key.length + key2.length];

        System.arraycopy(key, 0, combined, 0, key.length);
        System.arraycopy(key2, 0, combined, key.length, key2.length);

        saveSecureKey(combined, preferencesKey);

        return combined;
    }

    private SharedPreferences getSharedPreference() {
        return context.getSharedPreferences(PREFERENCES_KEY, Context.MODE_PRIVATE);
    }
}
