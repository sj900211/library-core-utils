package run.freshr.common.utils;

import static java.util.Optional.ofNullable;

import java.text.DecimalFormat;
import java.util.Objects;
import java.util.Random;
import java.util.UUID;

/**
 * 문자 Util
 *
 * @author FreshR
 * @apiNote 문자 데이터를 쉽게 사용하기 위한 Util
 * @since 2024. 3. 26. 오후 3:01:38
 */
public class StringUtil {

  /**
   * 음절 목록화
   *
   * @param value 음절 목록으로 변환할 문자
   * @return 변환한 음절 목록
   * @apiNote 문자를 음절 목록으로 변환하여 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static char[] toChar(final String value) {
    return Objects.toString(value).toCharArray();
  }

  /**
   * 앞 자리수 채우기
   *
   * @param value 값
   * @param size  자리수
   * @return 자리수만큼 0으로 앞 공간이 채워진 문자
   * @apiNote 값을 자리수만큼 남는 앞 공간을 0으로 채워서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String padding(final Number value, final Integer size) {
    return padding(value, "0", size);
  }

  /**
   * 앞 자리수 채우기
   *
   * @param value       값
   * @param paddingWord 빈 자리수에 채워질 문자
   * @param size        자리수
   * @return 자리수만큼 빈 자리수에 채워질 문자로 앞 공간이 채워진 문자
   * @apiNote 값을 자리수만큼 남는 앞 공간을 자리수에 채워질 문자로 채워서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String padding(final Number value, final String paddingWord, final Integer size) {
    return new DecimalFormat(String.valueOf(paddingWord)
        .repeat(Math.max(0, size)))
        .format(ofNullable(value).orElse(0).longValue());
  }

  /**
   * 세 자리 콤마
   *
   * @param value 값
   * @return 세자리마다 콤마가 들어간 값
   * @apiNote 전달된 값을 세자리마다 콤마를 추가해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String comma(final Number value) {
    return separate(value.toString(), 3, ",");
  }

  /**
   * 구문 문자 추가
   *
   * @param value     값
   * @param length    자리수
   * @param separator 구분 문자
   * @return 전달된 자리수마다 전달된 구분 문자를 추가한 값
   * @apiNote 전달된 값에 전달된 자리수마다 전달된 구분 문자를 추가한 값을 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String separate(final String value, final Number length, final String separator) {
    StringBuffer reverseValue = new StringBuffer(value).reverse();
    int reverseLength = reverseValue.toString().length();

    StringBuilder stringBuilder = new StringBuilder();

    int number = ofNullable(length).orElse(0).intValue();

    for (int i = 0; i < reverseLength; i++) {
      if (i % number == 0 && i != 0) {
        stringBuilder.append(separator);
      }

      stringBuilder.append(reverseValue.charAt(i));
    }

    return stringBuilder.reverse().toString();
  }

  /**
   * 임의의 16진수 문자
   *
   * @param limit 길이
   * @return 전달된 길이의 랜덤한 16진수 문자
   * @apiNote 전달된 길이만큼 랜덤한 16진수 문자를 생성해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String hex(final Integer limit) {
    StringBuilder hex = new StringBuilder();

    for (int i = 0; i < limit; i++) {
      hex.append(Integer.toHexString(new Random().nextInt(16)));
    }

    return hex.toString();
  }

  /**
   * 임의의 문자
   *
   * @param limit 길이
   * @return 전달된 길이의 랜덤한 정수 문자
   * @apiNote 전달된 길이만큼 랜덤한 정수 문자를 생성해서 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String random(final Integer limit) {
    StringBuilder random = new StringBuilder();

    for (int i = 0; i < limit; i++) {
      random.append(new Random().nextInt(10));
    }

    return random.toString();
  }

  /**
   * UUID 생성 및 반환
   *
   * @return string
   * @apiNote Version 4 UUID 생성 및 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String uuid() {
    return UUID.randomUUID().toString();
  }

  /**
   * hyphen 을 제거한 UUID 생성 및 반환
   *
   * @return string
   * @apiNote hyphen 을 제거한 Version 4 UUID 생성 및 반환
   * @author FreshR
   * @since 2024. 3. 26. 오후 3:01:38
   */
  public static String uuidWithoutHyphen() {
    return uuid().replace("-", "");
  }

}
