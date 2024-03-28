package run.freshr.common.configurations;

import static java.util.Optional.ofNullable;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import run.freshr.common.data.UtilsData;
import run.freshr.common.properties.UtilsProperties;

/**
 * Utils 설정
 *
 * @author FreshR
 * @apiNote application.properties 와 application.yml 에서 설정한 값과<br>
 *          기본 설정 값으로 Utils 데이터 객체 설정
 * @since 2024. 3. 27. 오후 2:26:53
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(UtilsProperties.class)
public class UtilsAutoConfiguration {

  /**
   * Utils 데이터 객체 설정
   *
   * @param properties application.properties 와 application.yml 에서 설정한 값
   * @return Utils 데이터 객체
   * @apiNote application.properties 와 application.yml 에서 설정한 값과<br>
   *          기본 설정 값으로 Utils 데이터 객체 설정
   * @author FreshR
   * @since 2024. 3. 27. 오후 2:26:53
   */
  @Bean
  @ConditionalOnMissingBean
  public UtilsData utilsData(UtilsProperties properties) {
    return UtilsData
        .builder()
        .encryptSalt(ofNullable(properties.getEncryptSalt()).orElse("FreshR"))
        .jwtSalt(ofNullable(properties.getJwtSalt()).orElse("FRESH-R"))
        .build();
  }

}
