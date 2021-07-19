import android.content.Context
import android.content.SharedPreferences
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

/**
 * DataEncryptor
 * Interface for encryption and decryption strings
 * DataEncryptor with Android KeyStore mechanism for securely encryption for all Android versions
 */

interface DataEncryptor {
    fun encryptString(src: String): String
    fun decryptString(src: String): String
}

/**
 * Modern encryption/decryption for Android API >= 23
 * (Android M and above)
 */

class DataEncryptorModern : DataEncryptor {

    companion object {
        private const val KEY_ALIAS = "KEY_ALIAS"
        private const val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
        private const val TAG_LENGTH = 128

        private const val TAG = "DataEncryptorModern"
    }

    private var INIT_VECTOR = "abcdefghijkl"
    private var cipher: Cipher = Cipher.getInstance(CIPHER_ALGORITHM)

    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
    private val keyGenerator: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER_ANDROID_KEY_STORE)

    override fun encryptString(src: String): String {
        return try {
            initCipher(Cipher.ENCRYPT_MODE)
            val encryptedBytes = cipher.doFinal(src.toByteArray())
            Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        } catch (ex: Exception) {
            Log.e(TAG, "encrypt(): $ex")
            ""
        }
    }

    override fun decryptString(src: String): String {
        return try {
            initCipher(Cipher.DECRYPT_MODE)
            val bytes = Base64.decode(src, Base64.NO_WRAP)
            return String(cipher.doFinal(bytes))
        } catch (ex: Exception) {
            Log.e(TAG, "decrypt(): $ex")
            ""
        }
    }

    private fun initCipher(mode: Int) {
        try {
            cipher.init(mode, getOrCreateKey(), getGcmSpec())
        } catch (invalidKeyException: KeyPermanentlyInvalidatedException) {
            Log.d(TAG, "initCipher(): Invalid Key: $invalidKeyException")
            deleteInvalidKey()
        } catch (ex: Exception) {
            Log.e(TAG, "initCipher(): $ex")
        }
    }

    private fun getOrCreateKey(): SecretKey {
        keyStore.load(null)
        if (!keyStore.containsAlias(KEY_ALIAS)) generateKey()
        return getExistingKey()
    }

    private fun generateKey() {
        keyGenerator.init(getKeyGenParams())
        keyGenerator.generateKey()
    }

    private fun getExistingKey(): SecretKey {
        keyStore.load(null)
        return (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun deleteInvalidKey() {
        keyStore.load(null)
        keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun getKeyGenParams(): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(false)
            .build()
    }

    private fun getGcmSpec(): GCMParameterSpec {
        return GCMParameterSpec(TAG_LENGTH, INIT_VECTOR.toByteArray())
    }

}

/**
 * Legacy encryption/decryption for Android API < 23
 * (older than Android M)
 */

class DataEncryptorLegacy(
    private val context: Context,
    private val sharedPreferences: SharedPreferences
) : DataEncryptor {

    companion object {
        private const val KEY_ALIAS = "KEY_ALIAS"
        private const val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val PROVIDER_BC = "BC"
        private const val CIPHER_ALGORITHM_LEGACY_RSA = "RSA/ECB/PKCS1Padding"
        private const val CIPHER_ALGORITHM_LEGACY_AES = "AES/ECB/PKCS7Padding"
        private const val LEGACY_KEY_ALG_TYPE = "AES"
        private const val SECRET_KEY_BUFFER_SIZE = 16

        private const val KEY_AES_LEGACY_KEY = "key_aes"

        private const val TAG = "DataEncryptorLegacy"
    }

    private var keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_RSA, PROVIDER_ANDROID_KEY_STORE
    )
    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
    private var cipher: Cipher = Cipher.getInstance(CIPHER_ALGORITHM_LEGACY_RSA, PROVIDER_ANDROID_KEY_STORE)

    override fun encryptString(src: String): String {
        getOrCreateSecretKeyLegacy()?.let { key ->
            try {
                initCipherForDataEncryption(Cipher.ENCRYPT_MODE, key)
                val encryptedBytes = cipher.doFinal(src.toByteArray())
                return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
            } catch (ex: Exception) {
                Log.e(TAG, "encryptStringLegacy(): $ex")
                ""
            }
        }
        Log.e(TAG, "encryptStringLegacy(): Secret key is empty")
        return ""
    }

    override fun decryptString(src: String): String {
        getOrCreateSecretKeyLegacy()?.let { key ->
            try {
                initCipherForDataEncryption(Cipher.DECRYPT_MODE, key)
                val decryptedBytes = cipher.doFinal(src.toByteArray())
                return Base64.encodeToString(decryptedBytes, Base64.NO_WRAP)
            } catch (ex: Exception) {
                Log.e(TAG, "decryptStringLegacy(): $ex")
                ""
            }
        }
        Log.e(TAG, "decryptStringLegacy(): Secret key is empty")
        return ""
    }

    private fun getOrCreateKeyPair(): KeyStore.PrivateKeyEntry {
        keyStore.load(null)
        if (!keyStore.containsAlias(KEY_ALIAS)) generateKeyPairLegacy()
        return getExistingKeyPairLegacy()
    }

    private fun generateKeyPairLegacy() {
        keyPairGenerator.initialize(getKeyGenParamsLegacy())
        keyPairGenerator.generateKeyPair()
    }

    private fun getExistingKeyPairLegacy(): KeyStore.PrivateKeyEntry {
        keyStore.load(null)
        return (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry)
    }

    private fun initCipherForKeyEncryption() {
        cipher = Cipher.getInstance(CIPHER_ALGORITHM_LEGACY_RSA, PROVIDER_ANDROID_KEY_STORE)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKeyPair().certificate.publicKey)
    }

    private fun initCipherForKeyDecryption() {
        cipher = Cipher.getInstance(CIPHER_ALGORITHM_LEGACY_RSA, PROVIDER_ANDROID_KEY_STORE)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKeyPair().privateKey)
    }

    private fun initCipherForDataEncryption(mode: Int, secretKey: Key) {
        cipher = Cipher.getInstance(CIPHER_ALGORITHM_LEGACY_AES, PROVIDER_BC)
        cipher.init(mode, secretKey)
    }

    private fun getOrCreateSecretKeyLegacy(): Key? {
        if (!sharedPreferences.contains(KEY_AES_LEGACY_KEY)) generateSecretKeyLegacy()
        return getSecretKeyLegacy()
    }

    private fun getSecretKeyLegacy(): Key? {
        val keyBase64 = sharedPreferences.getString(KEY_AES_LEGACY_KEY, null)
        return if (keyBase64 != null) {
            val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
            val keyBytesDecrypted = decryptSecretKeyRsa(keyBytes)
            SecretKeySpec(keyBytesDecrypted, LEGACY_KEY_ALG_TYPE)
        } else {
            null
        }
    }

    private fun generateSecretKeyLegacy() {
        val key = ByteArray(SECRET_KEY_BUFFER_SIZE)
        SecureRandom().nextBytes(key)
        val encryptedKey = encryptSecretKeyRsa(key)
        val keyBase64 = Base64.encodeToString(encryptedKey, Base64.NO_WRAP)
        sharedPreferences.edit()
            .putString(KEY_AES_LEGACY_KEY, keyBase64)
            .apply()
    }

    private fun encryptSecretKeyRsa(secretKeyBytes: ByteArray): ByteArray {
        return try {
            initCipherForKeyEncryption()
            val outputStream = ByteArrayOutputStream()
            val cipherOutputStream = CipherOutputStream(outputStream, cipher)
            cipherOutputStream.write(secretKeyBytes)
            cipherOutputStream.close()
            outputStream.toByteArray()
        } catch (ex: Exception) {
            Log.e(TAG, "encryptSecretKeyRsa() LEGACY: $ex")
            byteArrayOf()
        }
    }

    private fun decryptSecretKeyRsa(encryptedSecretKeyBytes: ByteArray): ByteArray {
        return try {
            initCipherForKeyDecryption()
            val cipherInputStream = CipherInputStream(ByteArrayInputStream(encryptedSecretKeyBytes), cipher)
            cipherInputStream.readBytes()
        } catch (ex: java.lang.Exception) {
            Log.e(TAG, "decryptSecretKeyRsa() LEGACY: $ex")
            byteArrayOf()
        }
    }

    private fun getKeyGenParamsLegacy(): KeyPairGeneratorSpec {
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(Calendar.YEAR, 30)
        return KeyPairGeneratorSpec.Builder(context)
            .setAlias(KEY_ALIAS)
            .setSubject(X500Principal("CN=$KEY_ALIAS"))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)
            .build()
    }

}
