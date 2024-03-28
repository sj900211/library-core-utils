package run.freshr.common.data;

import lombok.Builder;
import lombok.Data;

/**
 * Utils 데이터 모델
 *
 * @author FreshR
 * @apiNote Utils 데이터 모델
 * @since 2024. 3. 27. 오후 2:12:49
 */
@Data
@Builder
public class UtilsData {

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
