package run.freshr.common.utils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import run.freshr.common.data.UtilsData;

/**
 * 암호화 Util
 *
 * @author FreshR
 * @apiNote 암복호화 Util
 * @since 2024. 3. 26. 오후 3:01:38
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CryptoUtil {

  /**
   * 기본 SALT
   *
   * @apiNote 기본 SALT 값
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static String SALT = "SALT";

  /**
   * AES256 기본 해시 반복 수
   *
   * @apiNote AES256 암호화 알고리즘에서 사용할 기본 해시 반복 수
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final int HASH_CYCLE = 70000;
  /**
   * AES256 기본 키 길이
   *
   * @apiNote AES256 암호화 알고리즘에서 사용할 기본 키 길이
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final int HASH_BIT = 256;
  /**
   * AES256 Cipher 기본 규칙
   *
   * @apiNote AES256 암호화에서 Cipher 객체를 초기화할 기본 규칙
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
  /**
   * AES256 SecretKeyFactory 기본 규칙
   *
   * @apiNote AES256 암호화에서 SecretKeyFactory 객체를 초기화할 기본 규칙
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final String SECRET_INSTANCE = "PBKDF2WithHmacSHA1";
  /**
   * AES256 SecretKeySpec 기본 규칙
   *
   * @apiNote AES256 암호화에서 SecretKeySpec 객체를 초기화할 기본 규칙
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final String SECRET_SPEC = "AES";
  /**
   * 기본 인코딩
   *
   * @apiNote 기본 인코딩 문자 포맷
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final String BASIC_ENCODE = "UTF-8";
  /**
   * RSA 기본 규칙
   *
   * @apiNote RSA 암호화에서 사용할 SecretKey 기본 규칙
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static final String RSA_VALUE = "RSA";

  @Autowired
  public CryptoUtil(UtilsData utilsData) {
    SALT = utilsData.getEncryptSalt();
  }

  /**
   * AES256 암호화
   *
   * @param plainText 암호화할 문자
   * @return 암호화 문자
   * @apiNote 전달된 문자를 AES256 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encryptAes256(final String plainText) {
    return encryptAes256(plainText, SALT);
  }

  /**
   * AES256 암호화
   *
   * @param plainText 암호화할 문자
   * @param salt      SALT 값
   * @return 암호화 문자
   * @apiNote 전달된 문자를 전달된 SALT 값을 이용해서 AES256 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encryptAes256(final String plainText, final String salt) {
    String result = null;

    try {
      final SecureRandom random = new SecureRandom();
      final byte[] bytes = new byte[20];

      random.nextBytes(bytes);

      final SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_INSTANCE);
      // 70000번 해시하여 256 bit 길이의 키를 만든다.
      final PBEKeySpec spec = new PBEKeySpec(salt.toCharArray(), bytes, HASH_CYCLE, HASH_BIT);
      final SecretKey secretKey = factory.generateSecret(spec);
      final SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), SECRET_SPEC);
      final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);

      cipher.init(ENCRYPT_MODE, secret);

      final AlgorithmParameters params = cipher.getParameters();
      final byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
      final byte[] encryptionTextBytes = cipher.doFinal(plainText.getBytes(UTF_8));
      final byte[] buffer = new byte[bytes.length + ivBytes.length + encryptionTextBytes.length];

      System.arraycopy(bytes, 0, buffer, 0, bytes.length);
      System.arraycopy(ivBytes, 0, buffer, bytes.length, ivBytes.length);
      System.arraycopy(
          encryptionTextBytes,
          0,
          buffer,
          bytes.length + ivBytes.length,
          encryptionTextBytes.length);

      result = getEncoder().encodeToString(buffer);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * AES256 복호화
   *
   * @param encryptText 복호화할 AES256 암호화 문자
   * @return 복호화 문자
   * @apiNote 전달된 문자를 AES256 복호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decryptAes256(final String encryptText) {
    return decryptAes256(encryptText, SALT);
  }

  /**
   * AES256 복호화
   *
   * @param encryptText 복호화할 AES256 암호화 문자
   * @param salt        SALT 값
   * @return 복호화 문자
   * @apiNote 전달된 문자를 전달된 SALT 값을 이용해서 AES256 복호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decryptAes256(final String encryptText, final String salt) {
    String result = null;

    try {
      final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
      final ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(encryptText));
      final byte[] bytes = new byte[20];

      buffer.get(bytes, 0, bytes.length);

      final byte[] ivBytes = new byte[cipher.getBlockSize()];

      buffer.get(ivBytes, 0, ivBytes.length);

      final byte[] encryptionTextBytes = new byte[
          buffer.capacity() - bytes.length - ivBytes.length];

      buffer.get(encryptionTextBytes);

      final SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_INSTANCE);
      final PBEKeySpec spec = new PBEKeySpec(salt.toCharArray(), bytes, HASH_CYCLE, HASH_BIT);

      cipher.init(
          DECRYPT_MODE,
          new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_SPEC),
          new IvParameterSpec(ivBytes)
      );

      result = new String(cipher.doFinal(encryptionTextBytes));
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * SHA256 암호화
   *
   * @param plainText 암호화할 문자
   * @return 암호화 문자
   * @apiNote 전달된 문자를 SHA256 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encryptSha256(final String plainText) {
    return encryptSha256(plainText, SALT);
  }

  /**
   * SHA256 암호화
   *
   * @param plainText 암호화할 문자
   * @param salt      SALT 값
   * @return 암호화 문자
   * @apiNote 전달된 문자를 전달된 SALT 값을 이용해서 SHA256 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encryptSha256(final String plainText, final String salt) {
    return createSha256(plainText, salt);
  }

  /**
   * RSA 키 쌍 생성
   *
   * @return RSA Key Pair
   * @apiNote 새로운 RSA Key Pair 를 생성해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static KeyPair getKeyPar() {
    KeyPair result = null;

    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_VALUE);

      keyPairGenerator.initialize(1024, new SecureRandom());

      result = keyPairGenerator.generateKeyPair();
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * RSA 공개키 문자화
   *
   * @param publicKey RSA 공개키
   * @return 문자로 변환된 RSA 공개키
   * @apiNote 전달된 RSA 공개키를 문자로 인코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encodePublicKey(final PublicKey publicKey) {
    return getEncoder().encodeToString(publicKey.getEncoded());
  }

  /**
   * RSA 비공개키 문자화
   *
   * @param privateKey RSA 비공개키
   * @return 문자로 변환된 RSA 비공개키
   * @apiNote 전달된 RSA 비공개키를 문자로 인코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encodePrivateKey(final PrivateKey privateKey) {
    return getEncoder().encodeToString(privateKey.getEncoded());
  }

  /**
   * RSA 공개키 문자 객체화
   *
   * @param base64PublicKey RSA 공개키 문자
   * @return RSA 공개키
   * @apiNote 전달된 RSA 공개키 문자를 공개키 객체로 변환해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static PublicKey decodePublicKey(final String base64PublicKey) {
    PublicKey result = null;

    try {
      byte[] decodedBytes = Base64.getDecoder().decode(base64PublicKey);

      result = KeyFactory.getInstance(RSA_VALUE)
          .generatePublic(new X509EncodedKeySpec(decodedBytes));
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * RSA 비공개키 객체화
   *
   * @param base64PrivateKey RSA 비공개키 문자
   * @return RSA 비공개키
   * @apiNote 전달된 RSA 공개키 문자를 비공개키 객체로 변환해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static PrivateKey decodePrivateKey(final String base64PrivateKey) {
    PrivateKey result = null;

    try {
      byte[] decodedBytes = Base64.getDecoder().decode(base64PrivateKey);

      result = KeyFactory.getInstance(RSA_VALUE)
          .generatePrivate(new PKCS8EncodedKeySpec(decodedBytes));
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * RSA 암호화
   *
   * @param plainText 암호화할 평문
   * @param publicKey RSA 공개키
   * @return RSA 암호화 문자
   * @apiNote RSA 공개키로 평문을 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encryptRsa(final String plainText, final PublicKey publicKey) {
    String result = null;

    try {
      Cipher cipher = Cipher.getInstance(RSA_VALUE);

      cipher.init(ENCRYPT_MODE, publicKey);

      result = getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * RSA 암호화
   *
   * @param plainText       암호화할 평문
   * @param base64PublicKey 문자로 인코딩된 RSA 공개키
   * @return RSA 암호화 문자
   * @apiNote 문자로 인코딩된 RSA 공개키로 평문을 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encryptRsa(final String plainText, final String base64PublicKey) {
    return encryptRsa(plainText, decodePublicKey(base64PublicKey));
  }

  /**
   * RSA 복호화
   *
   * @param encryptText 복호화할 RSA 암호문
   * @param privateKey  RSA 비공개키
   * @return 복호화한 평문
   * @apiNote RSA 비공개키로 암호문을 복호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decryptRsa(final String encryptText, final PrivateKey privateKey) {
    String result = null;

    try {
      Cipher cipher = Cipher.getInstance(RSA_VALUE);
      byte[] encryptBytes = Base64.getDecoder().decode(encryptText.getBytes());

      cipher.init(DECRYPT_MODE, privateKey);

      byte[] decryptBytes = cipher.doFinal(encryptBytes);

      result = new String(decryptBytes, UTF_8);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * RSA 복호화
   *
   * @param plainText        복호화할 RSA 암호문
   * @param base64PrivateKey 문자로 인코딩된 RSA 비공개키
   * @return 복호화한 평문
   * @apiNote RSA 암호화된 문자를 비공개키로 복호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decryptRsa(final String plainText, final String base64PrivateKey) {
    return decryptRsa(plainText, decodePrivateKey(base64PrivateKey));
  }

  /**
   * BASE64 인코딩
   *
   * @param plainText 인코딩할 평문
   * @return BASE64 인코딩 문자
   * @apiNote 평문을 BASE64 인코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encodeBase64(final String plainText) {
    String result = null;

    try {
      result = getEncoder().encodeToString(plainText.getBytes());
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * BASE64 디코딩
   *
   * @param encodingText 디코딩할 BASE64 문자
   * @return BASE64 디코딩한 평문
   * @apiNote BASE64 인코딩한 문자를 디코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decodeBase64(final String encodingText) {
    String result = null;

    try {
      result = new String(Base64.getDecoder().decode(encodingText));
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * BASE64 디코딩
   *
   * @param encodingByte 디코딩할 BASE64 문자 Byte
   * @return BASE64 디코딩한 평문
   * @apiNote BASE64 인코딩한 문자를 디코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decodeBase64(final byte[] encodingByte) {
    String result = null;

    try {
      result = new String(Base64.getDecoder().decode(encodingByte));
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }


  /**
   * URL 인코딩
   *
   * @param plainText URL 인코딩할 평문
   * @return URL 인코딩 문자
   * @apiNote 평문을 URL 인코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String encodeUrl(final String plainText) {
    String result = null;

    try {
      result = URLEncoder.encode(plainText, BASIC_ENCODE);
    } catch (UnsupportedEncodingException e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * URL 디코딩
   *
   * @param encodingText URL 디코딩할 문자
   * @return URL 디코딩 문자
   * @apiNote URL 인코딩한 문자를 디코딩해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String decodeUrl(final String encodingText) {
    String result = null;

    try {
      result = URLDecoder.decode(encodingText, BASIC_ENCODE);
    } catch (UnsupportedEncodingException e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

  /**
   * SHA256 암호화
   *
   * @param plainText 암호화할 평문
   * @param salt      SALT 문자
   * @return SHA256 암호화 문자
   * @apiNote 평문을 SHA 암호화해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  private static String createSha256(final String plainText, final String salt) {
    String result = "";

    byte[] byteMsg = plainText.getBytes();
    byte[] byteSalt = salt.getBytes();
    byte[] bytes = new byte[byteMsg.length + byteSalt.length];

    System.arraycopy(byteMsg, 0, bytes, 0, byteMsg.length);
    System.arraycopy(byteSalt, 0, bytes, byteMsg.length, byteSalt.length);

    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

      messageDigest.update(bytes);

      byte[] byteData = messageDigest.digest();

      StringBuilder stringBuffer = new StringBuilder();

      for (byte byteDatum : byteData) {
        stringBuffer.append(Integer.toString((byteDatum & 0xFF) + 256, 16)
            .substring(1));
      }

      result = stringBuffer.toString();
    } catch (NoSuchAlgorithmException e) {
      log.error(e.getMessage(), e);
    }

    return result;
  }

}
