package run.freshr.common.utils;

import static io.jsonwebtoken.Jwts.SIG.HS512;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;
import static org.springframework.util.StringUtils.hasLength;
import static run.freshr.common.utils.CryptoUtil.encodeBase64;
import static run.freshr.common.utils.CryptoUtil.encryptSha256;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.HashMap;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import run.freshr.common.data.UtilsData;

/**
 * JWT Util
 *
 * @author FreshR
 * @apiNote JWT Util
 * @since 2024. 3. 27. 오후 2:35:01
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtil {

  public static String JWT_VARIABLE = "JWT";

  public static final String JWT_SHA = encryptSha256(JWT_VARIABLE);
  public static final byte[] JWT_BYTE = encodeBase64(JWT_SHA).getBytes(UTF_8); // JWT 암호화 키 Byte
  public static final SecretKey JWT_KEY = Keys.hmacShaKeyFor(JWT_BYTE); // Key 생성

  @Autowired
  public JwtUtil(UtilsData utilsData) {
    JWT_VARIABLE = utilsData.getJwtSalt();
  }

  /**
   * 토큰 발급
   *
   * @param subject subject
   * @return string
   * @apiNote 만료 시간이 없는 토큰 발급
   * @author FreshR
   * @since 2024. 3. 29. 오전 9:42:31
   */
  public static String generate(final String subject) {
    return generate(subject, null, null);
  }

  /**
   * 토큰 발급
   *
   * @param subject subject
   * @return string
   * @apiNote 토큰 발급
   * @author FreshR
   * @since 2024. 3. 29. 오전 9:42:31
   */
  public static String generate(final String subject, final Long expiration) {
    return generate(subject, expiration, null);
  }

  /**
   * 토큰 발급
   *
   * @param subject subject
   * @param claims  claims
   * @return string
   * @apiNote 만료 시간이 없는 토큰 발급
   * @author FreshR
   * @since 2024. 3. 27. 오후 5:47:20
   */
  public static String generate(final String subject, final HashMap<String, Object> claims) {
    return generate(subject, null, claims);
  }

  /**
   * 토큰 발급
   *
   * @param subject    토큰 제목
   * @param expiration 만료 기간
   * @param claims     토큰 claims
   * @return string
   * @apiNote 토큰 발급
   * @author FreshR
   * @since 2024. 3. 27. 오후 2:35:01
   */
  public static String generate(final String subject, final Long expiration,
      final HashMap<String, Object> claims) {
    JwtBuilder jwtBuilder = Jwts.builder()
        .header().add("typ", "JWT")
        .and()
        .subject(subject)
        .issuedAt(new Date())
        .signWith(JWT_KEY);

    if (!isNull(claims)) { // 토큰 Body 설정
      jwtBuilder.claims(claims);
    }

    if (!isNull(expiration)) { // 만료 시간 설정
      jwtBuilder.expiration(new Date(new Date().getTime() + expiration));
    }

    return jwtBuilder.compact();
  }

  /**
   * JWT 토큰 정보를 조회
   *
   * @param jwt jwt 토큰
   * @return claims
   * @throws JwtException jwt exception
   * @apiNote JWT 토큰 정보를 조회
   * @author FreshR
   * @since 2024. 3. 27. 오후 2:35:01
   */
  public static Claims get(final String jwt) throws JwtException {
    return Jwts.parser()
        .decryptWith(JWT_KEY)
        .build()
        .parseSignedClaims(jwt)
        .getPayload();
  }

  /**
   * 토큰이 만료되었는지 체크
   *
   * @param token JWT 토큰
   * @return boolean
   * @apiNote 토큰이 만료되었는지 체크
   * @author FreshR
   * @since 2024. 3. 27. 오후 2:35:01
   */
  public static boolean validateExpired(final String token) {
    if (!hasLength(token)) {
      return true;
    }

    return !checkExpiration(token);
  }

  /**
   * 토큰이 만료되었는지 체크
   *
   * @param jwt JWT 토큰
   * @return boolean
   * @throws JwtException jwt exception
   * @apiNote 토큰이 만료되었는지 체크
   * @author FreshR
   * @since 2024. 3. 27. 오후 2:35:01
   */
  public static boolean checkExpiration(final String jwt) throws JwtException {
    boolean flag = false;

    try {
      get(jwt);
    } catch (ExpiredJwtException e) {
      flag = true;
    }

    return flag;
  }

}
