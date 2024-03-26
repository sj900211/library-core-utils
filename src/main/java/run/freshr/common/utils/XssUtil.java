package run.freshr.common.utils;

import static org.jsoup.safety.Safelist.basic;

import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;

/**
 * XSS Util
 *
 * @author FreshR
 * @apiNote XSS 처리를 쉽게 사용하기 위한 Util
 * @since 2024. 3. 26. 오후 3:01:38
 */
public class XssUtil {

  /**
   * XSS 처리
   *
   * @param value XSS 처리할 문자
   * @return XSS 처리된 문자
   * @apiNote 전달된 문자를 XSS 처리해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String xssBasic(final String value) {
    return Jsoup.clean(value, basic());
  }

  /**
   * XSS 처리
   *
   * @param value XSS 처리할 문자
   * @return XSS 처리된 문자
   * @apiNote 전달된 문자를 img 요소를 제외하고 XSS 처리해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String xssBasicIgnoreImg(final String value) {
    return Jsoup.clean(
        value,
        basic().addTags("img")
            .addAttributes("img", "align", "alt", "height", "src", "title", "width")
            .addProtocols("img", "src", "http", "https")
    );
  }

}
