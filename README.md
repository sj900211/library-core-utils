# Library > Core > Utils
> 특정 기능이 필요하지 않은 자주 사용하는 메서드 정의
> - ## [BeanUtil](./src/main/java/run/freshr/common/utils/BeanUtil.java)
>> Spring Application Context 에 등록된 Bean 객체를 조회 및 사용 기능 정의  
>> 최대한 사용하지 않는 것을 권장
> - ## [CryptoUtil](./src/main/java/run/freshr/common/utils/CryptoUtil.java)
>> Encoding, Decoding, Encrypt, Decrypt 기능 정의
> - ## [MapperUtil](./src/main/java/run/freshr/common/utils/MapperUtil.java)
>> Model Mapper 기능 정의
> - ## [StringUtil](./src/main/java/run/freshr/common/utils/StringUtil.java)
>> 문자 관련 기능 정의
> - ## [XssUtil](./src/main/java/run/freshr/common/utils/XssUtil.java)
>> XSS 기능 정의
> - ## [JwtUtil](./src/main/java/run/freshr/common/utils/JwtUtil.java)
>> JWT 기능 정의
> - ## [UtilsProperties](./src/main/java/run/freshr/common/properties/UtilsProperties.java)
>> 프로젝트에 따라 변경되는 예외 항목의 정보를 변경할 수 있는 Properties 정의  
>> 프로젝트에서 사용할 때에는 application.yml 에서 각 정보를 변경할 수 있다.
>> ``` yaml
>> freshr:
>>   utils:
>>     encrypt-salt: "SALT-VALUE"
>> ```
>> 위처럼 변경하면 UtilsData 에 설정된다.  
>> UtilsProperties 에서는 lowerCameCase 형식이었지만  
>> application.yml 에서는 lower-hypen 으로 작성된다.
> - ## [UtilsAutoConfiguration](./src/main/java/run/freshr/common/configurations/UtilsAutoConfiguration.java)
>> UtilsProperties 에 설정한 값으로 ExceptionsData 를 빌드한다.
> - ## [UtilsData](./src/main/java/run/freshr/common/data/UtilsData.java)
>> UtilsProperties 에 설정한 값으로 빌드되는 Class.  
>> 이 Class 를 프로젝트에서 주입받아 사용