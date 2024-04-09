package run.freshr.common.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Util 속성 정의
 *
 * @author FreshR
 * @apiNote Util 속성을 정의해서 application.properties 또는 application.yml 에서 사용할 수 있도록 설정
 * @since 2024. 3. 27. 오후 2:12:49
 */
@Data
@ConfigurationProperties("freshr.utils")
public class UtilsProperties {

  /**
   * 암호화 SALT 데이터
   *
   * @apiNote 암호화 SALT 데이터
   * @since 2024. 3. 27. 오후 2:12:49
   */
  private String encryptSalt;
  /**
   * JWT SALT 데이터
   *
   * @apiNote JWT SALT 데이터
   * @since 2024. 3. 27. 오후 2:12:49
   */
  private String jwtSalt;

}
