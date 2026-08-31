# vault-crypto 기반 DB 컬럼 암호화 개발 가이드 (Spring Boot + MyBatis)

Spring Boot + MyBatis + PostgreSQL + Redis + HashiCorp Vault 환경(demoApp과 동일한 스택)에서 `vault-crypto` 라이브러리로 DB 컬럼 암호화를 **처음부터 구축**할 때 필요한 내용을 전부 다루는 가이드입니다. 예제 DB 오브젝트는 demoApp의 `users` 테이블을 기준으로 합니다 - 이 테이블은 아래 두 성격의 암호화 컬럼을 모두 가지고 있어 예제로 적합합니다.

| 컬럼 | 암호화 방식 | 성격 |
|---|---|---|
| `users.password` | BCrypt (`PasswordHasher`) | **단방향** - 원문 복구 불가, "맞는지"만 검증 |
| `users.id_no`, `users.phone` | AES-256-GCM KEK-DEK 봉투 암호화 (`EnvelopeCryptoService`) | **양방향** - `decrypt()`로 원문 복원 가능 |
| `users.id_no_blind_idx`, `users.phone_blind_idx` | HMAC-SHA256 (`BlindIndexService`) | 양방향 컬럼의 **검색 전용** 결정적 인덱스 (평문 컬럼) |

이 문서가 다루지 않는 것 - 필요하면 아래 문서를 참고하세요:
- 라이브러리 자체의 클래스/API 상세: [`README.md`](README.md) (이 저장소)
- 조회 상황별 패턴과 실전 실수 사례 상세: [`ENCRYPTED_COLUMN_QUERY_GUIDE.md`](../demoApp/ENCRYPTED_COLUMN_QUERY_GUIDE.md) (demoApp 저장소) (이 문서와 내용이 겹치는 곳은 요약만 하고 그쪽으로 링크했습니다)
- KEK/DEK 로테이션 운영 절차: [`KEY_ROTATION_RUNBOOK.md`](../demoApp/KEY_ROTATION_RUNBOOK.md) (demoApp 저장소)
- 전체 아키텍처 도입 배경: [`KEK_DEK_ENCRYPTION_PLAN.md`](../demoApp/KEK_DEK_ENCRYPTION_PLAN.md) (demoApp 저장소)

---

## 목차

0. [핵심 설계 원칙](#0-핵심-설계-원칙)
1. [사전 준비 - 의존성 · Vault · 설정 · 스키마](#1-사전-준비---의존성--vault--설정--스키마)
2. [암호화 컬럼 CRUD 구현 방안](#2-암호화-컬럼-crud-구현-방안)
3. [양방향 암호화 컬럼 조건 조회 - Blind Index](#3-양방향-암호화-컬럼-조건-조회---blind-index)
4. [단방향 암호화 컬럼 조건 조회](#4-단방향-암호화-컬럼-조건-조회)
5. [Redis 캐싱을 고려한 앱 구현 방안](#5-redis-캐싱을-고려한-앱-구현-방안)
6. [테스트 작성 방법 - Vault 없이 단위 테스트](#6-테스트-작성-방법---vault-없이-단위-테스트)
7. [로깅 · 마스킹 · 트랜잭션 주의사항](#7-로깅--마스킹--트랜잭션-주의사항)
8. [신규 암호화 컬럼 추가 체크리스트](#8-신규-암호화-컬럼-추가-체크리스트)
9. [흔한 실수 요약](#9-흔한-실수-요약)

---

## 0. 핵심 설계 원칙

1. **Service는 평문만 다룬다.** 암/복호화는 MyBatis `TypeHandler`가 Mapper 경계(JDBC 파라미터 설정 / `ResultSet` 읽기)에서 투명하게 처리한다. `UserService`가 `EnvelopeCryptoService.encrypt()`/`decrypt()`를 직접 호출하는 코드가 새로 생긴다면, 십중팔구 TypeHandler로 옮길 수 있는 코드다.
2. **컬럼마다 "원문이 다시 필요한가"로 방식을 고른다.** 다시 볼 필요가 없으면(로그인 비밀번호) BCrypt(`PasswordHasher`), 나중에 원문이 필요하면(개인정보, 게시글 비밀번호) KEK-DEK 봉투 암호화(`EnvelopeCryptoService`).
3. **양방향 암호화 컬럼은 등호(`=`)/부분(`LIKE`) 검색이 원천적으로 불가능하다.** AES-GCM은 매번 랜덤 IV를 쓰므로 같은 평문도 암호문이 매번 다르다. 정확 일치 검색이 필요하면 Blind Index(결정적 HMAC) 컬럼을 별도로 둔다.
4. **레거시/비정형 데이터가 섞인 컬럼은 읽기 경로에 TypeHandler를 걸지 않는다.** 한 행의 복호화 실패가 그 행을 스치는 모든 `SELECT`를 예외로 깨뜨리기 때문이다. `users` 테이블은 KEK-DEK 도입 시점에 초기화되어 레거시 데이터가 없으므로 이 문제에서 자유롭다 - 새 프로젝트에서 신규 테이블을 만든다면 이 조건을 항상 만족하지만, 기존 운영 테이블에 암호화를 나중에 적용한다면 반드시 이 표로 먼저 판단해야 한다([`ENCRYPTED_COLUMN_QUERY_GUIDE.md` §2](../demoApp/ENCRYPTED_COLUMN_QUERY_GUIDE.md#2-컬럼마다-성격이-다르다---먼저-이것부터-판단) 참고).
5. **캐시에는 절대 복호화된 평문을 올리지 않는다.** Redis 등 외부 캐시에 저장되는 값은 항상 암호문(ciphertext) 상태여야 하고, 복호화는 캐시를 거친 뒤 애플리케이션 메모리에서만 수행한다.

---

## 1. 사전 준비 - 의존성 · Vault · 설정 · 스키마

### 1-1. Gradle 의존성

```groovy
plugins {
    id 'org.springframework.boot' version '3.4.0'
    id 'io.spring.dependency-management' version '1.1.6'
}

ext {
    set('springCloudVersion', '2024.0.0')
}

repositories {
    mavenCentral()
    mavenLocal()   // vault-crypto는 사내 로컬 Maven 저장소에서 로드
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.mybatis:mybatis:3.5.16'
    implementation 'org.mybatis.spring.boot:mybatis-spring-boot-starter:3.0.4'
    implementation 'org.springframework.cloud:spring-cloud-starter-vault-config'
    implementation 'org.springframework.boot:spring-boot-starter-actuator'

    // vault-crypto: KEK-DEK 봉투 암호화 + BCrypt + Blind Index - 암호/PII 크립토 로직은 전부 여기서 온다
    implementation 'com.xaan:vault-crypto:0.0.10'

    implementation 'org.springframework.boot:spring-boot-starter-data-redis'

    runtimeOnly 'org.postgresql:postgresql'
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}

dependencyManagement {
    imports {
        mavenBom "org.springframework.cloud:spring-cloud-dependencies:${springCloudVersion}"
    }
}
```

> `vault-crypto`는 이걸 사용하는 Spring Boot 프로젝트(demoApp 등)와 별도 저장소로 관리된다. 새 버전이 필요하면 이 저장소(vault-crypto)에서 `gradle.bat clean build publishToMavenLocal`(Windows) / `./gradlew clean build publishToMavenLocal`(Linux)로 로컬 Maven에 설치한 뒤, 소비 프로젝트의 `build.gradle`에서 버전을 올린다.

### 1-2. Vault 사전 준비

`vault-crypto`는 성격이 다른 세 종류의 키를 Vault kv-v2에 저장한다. **BCrypt(단방향)는 외부 키가 필요 없어 Vault와 완전히 무관하다** - 아래 준비는 양방향 암호화(id_no, phone)와 그 검색(Blind Index)에만 필요하다.

```bash
# 1) kv-v2 백엔드 활성화 (최초 1회)
vault secrets enable -path=ebiz_service kv-v2

# 2) KEK(마스터 키) - 버전별 필드 + current-version 포인터
vault kv put -mount=ebiz_service ebiz_db/kek \
  kek-v1="<Base64URL 32바이트 랜덤 키>" \
  current-version="1"

# 3) 도메인별 DEK (KEK로 wrap된 상태로 저장) - id_no/phone은 같은 user-pii 도메인
#    wrap()의 출력 자체에 kekVersion 헤더가 포함되므로 별도 부트스트랩 스크립트로 생성한다
#    (demoApp의 bootstrap_kek_dek.py 참고 - vault kv put 명령만 출력하고 Vault를 직접 건드리지 않음)
vault kv put -mount=ebiz_service ebiz_db/dek/user-pii \
  dek-v1="<Base64URL(kekVersion+IV+ciphertext+tag)>" \
  current-version="1"

# 4) Blind Index 키 - 필드마다 1개, DEK와 무관한 별도 키 (버전 관리 없음)
vault kv put -mount=ebiz_service ebiz_db/blind-index/user-phone \
  key="<Base64URL 32바이트 랜덤 키>"
vault kv put -mount=ebiz_service ebiz_db/blind-index/user-rrn \
  key="<Base64URL 32바이트 랜덤 키>"
```

demoApp의 부트스트랩 스크립트(`bootstrap_kek_dek.py`, `bootstrap_blind_index_keys.py`)는 위 명령들을 생성만 해줄 뿐 Vault에 직접 쓰지 않는다 - 출력된 명령을 검토한 뒤 직접 실행한다. Blind Index 키가 없으면 `BlindIndexService` 빈 생성이 fail-fast로 앱 시작 자체를 막으므로, 신규 필드를 추가할 때 이 단계를 빠뜨리면 배포 직후 앱이 뜨지 않는다.

### 1-3. application.properties

```properties
mybatis.configuration.map-underscore-to-camel-case=true

spring.datasource.url=jdbc:postgresql://${DB_HOST:localhost}:${DB_PORT:5432}/limadb?currentSchema=${DB_SCHEMA:ebiz}
spring.datasource.username=${DB_USERNAME:postgres}
spring.datasource.password=${DB_PASSWORD:changeme}

spring.cloud.vault.uri=${VAULT_URI:http://192.168.2.57:8200}
spring.cloud.vault.token=${VAULT_TOKEN}
spring.cloud.vault.fail-fast=true

vault.kek.path=${VAULT_KEK_PATH:ebiz_service/data/ebiz_db/kek}
vault.dek.base-path=${VAULT_DEK_BASE_PATH:ebiz_service/data/ebiz_db/dek}
vault.blind-index.base-path=${VAULT_BLIND_INDEX_BASE_PATH:ebiz_service/data/ebiz_db/blind-index}

# Redis 캐싱 (5장)
spring.data.redis.host=${REDIS_HOST:192.168.2.57}
spring.data.redis.port=${REDIS_PORT:6379}
spring.cache.type=redis
spring.cache.redis.time-to-live=5m
```

`mybatis.configuration.map-underscore-to-camel-case=true`는 필수다 - 이게 없으면 `id_no`처럼 명시적 `@Result` 매핑이 없는 snake_case 컬럼이 조용히 `null`로 들어온다(에러 없음).

### 1-4. CryptoConfig - 빈 구성

```java
@Configuration
public class CryptoConfig {

    public static final byte USER_PII_DOMAIN_CODE = 2; // 도메인마다 고유한 1바이트 값

    @Bean
    public KekProvider kekProvider(VaultOperations vaultOperations,
            @Value("${vault.kek.path}") String kekPath) {
        return new VaultKekProvider(vaultOperations, kekPath);
    }

    @Bean
    public KekService kekService(KekProvider kekProvider) {
        return KekService.load(kekProvider); // 모든 KEK 버전을 앱 기동 시 1회 로드
    }

    @Bean
    public DekProvider dekProvider(VaultOperations vaultOperations,
            @Value("${vault.dek.base-path}") String dekBasePath) {
        return new VaultDekProvider(vaultOperations, dekBasePath);
    }

    // 도메인마다 빈 하나 - 여기서는 users의 id_no/phone을 묶는 user-pii 도메인 하나만 예시
    @Bean
    public EnvelopeCryptoService userPiiCryptoService(KekService kekService, DekProvider dekProvider) {
        return EnvelopeCryptoService.forDomain(USER_PII_DOMAIN_CODE, "user-pii", kekService, dekProvider);
    }

    @Bean
    public BlindIndexKeyProvider blindIndexKeyProvider(VaultOperations vaultOperations,
            @Value("${vault.blind-index.base-path}") String basePath) {
        return new VaultBlindIndexKeyProvider(vaultOperations, basePath);
    }

    // 필드마다 빈 하나 - indexName은 필드마다 고유한 문자열
    @Bean
    public BlindIndexService phoneBlindIndexService(BlindIndexKeyProvider provider) {
        return BlindIndexService.forIndex("user-phone", provider);
    }

    @Bean
    public BlindIndexService rrnBlindIndexService(BlindIndexKeyProvider provider) {
        return BlindIndexService.forIndex("user-rrn", provider);
    }
}
```

`forDomain(...)` 호출 시점(빈 생성, 즉 앱 기동 시)에 DEK가 1회 unwrap되어 메모리에 캐시된다 - 이후 요청 시점의 `encrypt()`/`decrypt()`/`validate()`는 Vault를 다시 호출하지 않는다. **여러 도메인을 쓸 때는 `domainCode` 값이 서로 겹치지 않도록 관리한다** - 겹치면 다른 도메인의 암호문을 잘못 복호화하려다 조용히 뒤섞일 수 있다(실제로는 `decrypt()`가 헤더의 domainCode로 검증하므로 즉시 `CryptoException`이 나지만, 애초에 코드 리뷰에서 걸러야 한다).

### 1-5. 테이블 스키마 - users 예제

```sql
CREATE TABLE ebiz.users (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            VARCHAR(50) NOT NULL UNIQUE,   -- 평문
    password           VARCHAR(255) NOT NULL,          -- BCrypt 해시 (단방향)
    username           VARCHAR(100) NOT NULL,          -- 평문
    id_no              VARCHAR(255),                   -- AES-GCM 암호문 (양방향)
    id_no_blind_idx    VARCHAR(64),                     -- id_no 검색용 HMAC (평문 컬럼)
    phone              VARCHAR(255),                    -- AES-GCM 암호문 (양방향)
    phone_blind_idx    VARCHAR(64)                      -- phone 검색용 HMAC (평문 컬럼)
);

CREATE INDEX idx_users_phone_blind_idx ON ebiz.users (phone_blind_idx);
CREATE INDEX idx_users_id_no_blind_idx ON ebiz.users (id_no_blind_idx);
```

**MyBatis는 JPA의 `ddl-auto`처럼 스키마를 관리하지 않는다.** 신규 컬럼/인덱스 추가는 `migrations/00N_*.sql` 형태로 SQL을 남기고 대상 DB에 수동 실행한다(demoApp의 `migrations/001_add_user_phone_and_blind_index.sql` 참고). 기존 행이 있는 컬럼에 Blind Index를 추가하면 그 컬럼은 `NULL`로 시작하므로, 검색이 기존 행까지 찾아야 한다면 "평문을 복호화 → HMAC 계산 → 백필" 배치를 별도로 돌려야 한다(id_no처럼 이미 값이 있던 컬럼이 이 경우).

---

## 2. 암호화 컬럼 CRUD 구현 방안

### 2-1. 도메인별 TypeHandler 서브클래스

`EnvelopeCryptoTypeHandler`는 `EnvelopeCryptoService` 하나에 고정되므로, 도메인마다(혹은 서로 다른 암/복호화 정책을 가진 컬럼마다) 서브클래스가 하나씩 필요하다. MyBatis가 `typeHandler=...`를 클래스로만 참조하기 때문이다.

```java
@Component
public class UserPiiTypeHandler extends EnvelopeCryptoTypeHandler {
    public UserPiiTypeHandler(@Qualifier("userPiiCryptoService") EnvelopeCryptoService userPiiCryptoService) {
        super(userPiiCryptoService);
    }
}
```

`@MappedTypes`를 붙이지 않는다 - `EnvelopeCryptoTypeHandler`는 (`BaseTypeHandler` 대신) 순수 `TypeHandler` 인터페이스를 구현하므로 MyBatis의 자동 타입 등록이 애초에 일어나지 않는다. 이 부분을 실수로 `BaseTypeHandler<String>`을 상속해서 직접 구현하면, 해당 핸들러가 앱 전체의 **모든** `String` 컬럼의 기본 핸들러가 되어버리는 심각한 사고로 이어진다(실제로 demoApp에서 한 번 발생 - 이 저장소의 v0.0.9→v0.0.10 릴리스 히스토리(`README.md`) 참고). **직접 TypeHandler를 새로 작성할 일은 없어야 한다 - 항상 `EnvelopeCryptoTypeHandler`를 상속만 한다.**

### 2-2. Create - INSERT

암호화 컬럼과 Blind Index 컬럼은 **같은 INSERT 문에서 함께** 저장한다(원자성 확보 - 하나만 저장되고 다른 하나가 빠지는 상태가 생기면 안 됨).

```java
@Mapper
public interface UserMapper {

    String INSERT_COLUMNS = "user_id, password, username, id_no, phone, id_no_blind_idx, phone_blind_idx";
    String INSERT_VALUES = "#{userId}, #{password}, #{username}, " +
            "#{residentRegistrationNumber,typeHandler=com.xaan.demo.config.mybatis.UserPiiTypeHandler}, " +
            "#{phone,typeHandler=com.xaan.demo.config.mybatis.UserPiiTypeHandler}, " +
            "#{residentRegistrationNumberBlindIndex}, #{phoneBlindIndex}";

    @Insert("insert into users (" + INSERT_COLUMNS + ") values (" + INSERT_VALUES + ")")
    @Options(useGeneratedKeys = true, keyProperty = "id", keyColumn = "id")
    int insert(User user);
}
```

```java
// UserService.register() - Service는 평문만 조립해서 넘긴다
User user = User.builder()
        .userId(dto.getUserId())
        .password(passwordService.hashUserPassword(dto.getPassword()))       // BCrypt (단방향)
        .username(dto.getUsername())
        .residentRegistrationNumber(dto.getResidentRegistrationNumber())     // 평문 그대로 - typeHandler가 암호화
        .phone(normalizedPhone)                                               // 평문 그대로 - typeHandler가 암호화
        .residentRegistrationNumberBlindIndex(passwordService.computeRrnBlindIndex(dto.getResidentRegistrationNumber()))
        .phoneBlindIndex(passwordService.computePhoneBlindIndex(normalizedPhone))
        .build();
userMapper.insert(user);
```

### 2-3. Read - 단건 조회

`users`는 레거시 데이터가 없는 테이블이므로 읽기 경로에도 TypeHandler를 걸어 자동 복호화할 수 있다(§0 원칙 4 참고). 이 조회는 "이 값 자체가 필요할 때"용이다 - 한 행의 복호화 실패는 예외로 알려주는 게 맞다(호출자가 문제를 인지해야 함).

```java
@Select("select id, user_id, password, username, id_no, phone, id_no_blind_idx, phone_blind_idx " +
        "from users where user_id = #{userId}")
@Results({
        @Result(column = "id_no", property = "residentRegistrationNumber", typeHandler = UserPiiTypeHandler.class),
        @Result(column = "phone", property = "phone", typeHandler = UserPiiTypeHandler.class),
        @Result(column = "id_no_blind_idx", property = "residentRegistrationNumberBlindIndex"),
        @Result(column = "phone_blind_idx", property = "phoneBlindIndex")
})
Optional<User> findByUserId(String userId);
```

**암호화 컬럼이 필요 없는 조회는 애초에 select하지 않는다.** 로그인 검증은 BCrypt 비밀번호 하나면 충분한데 `id_no`/`phone`까지 같이 조회해 복호화하면, 그 PII 컬럼의 ciphertext 문제(예: 과거 키 재발급으로 무효화된 값) 하나가 **비밀번호가 맞는 계정의 로그인 자체를 막아버린다.** 필요한 컬럼만 뽑는 조회 메서드를 별도로 둔다:

```java
@Select("select id, user_id, password, username from users where user_id = #{userId}")
Optional<User> findAuthByUserId(String userId);
```

### 2-4. Read - 목록/여러 행 조회

여러 행을 한 번에 반환하는 조회에 typeHandler를 읽기 경로에 걸면, **행 하나의 ciphertext 문제가 전체 조회를 예외로 죽인다.** 레거시가 없는 테이블이라도 과거 키 재발급 등으로 특정 행만 복호화가 안 되는 경우가 실제로 있었으므로, 목록 조회는 다음 두 단계로 나눈다.

```java
// Mapper - typeHandler 없이 raw(ciphertext) 그대로 반환
@Select("""
        <script>
        select id, user_id, password, username, id_no, phone, id_no_blind_idx, phone_blind_idx
        from users
        <where>
            <if test="name != null and name != ''">
                and username like concat('%', #{name}, '%')
            </if>
        </where>
        order by id desc
        </script>
        """)
@Results({
        @Result(column = "id_no", property = "residentRegistrationNumber"),
        @Result(column = "phone", property = "phone")
})
List<User> search(@Param("name") String name);
```

```java
// Service - 행마다 개별 복호화를 시도, 실패하면 그 행만 대체 문자열
public List<UserResponseDto> search(String name) {
    return userMapper.search(name).stream()
            .map(user -> new UserResponseDto(
                    user,
                    passwordService.decryptUserPiiForDisplay(user.getResidentRegistrationNumber()),
                    passwordService.decryptUserPiiForDisplay(user.getPhone())))
            .collect(Collectors.toList());
}
```

```java
// PasswordService - 실패해도 던지지 않고 대체 문자열 반환
public String decryptUserPiiForDisplay(String encryptedText) {
    if (encryptedText == null || encryptedText.isEmpty()) return encryptedText;
    try {
        return userPiiCryptoService.decrypt(encryptedText);
    } catch (RuntimeException e) {
        logger.warn("Failed to decrypt user-pii value for display: {}", e.getMessage());
        return "(복호화 실패)";
    }
}
```

### 2-5. Update

**값이 실제로 바뀔 때만** typeHandler가 걸린 파라미터를 SQL에 포함시킨다. 바뀌지 않은 기존 값(이미 암호문)을 typeHandler가 있는 파라미터로 다시 흘려보내면 **이중 암호화**가 되어 이후 복호화가 불가능해진다.

```java
// id_no를 바꾸는 경우 - typeHandler를 통해 새로 암호화
@Update("update users set id_no = #{residentRegistrationNumber,typeHandler=com.xaan.demo.config.mybatis.UserPiiTypeHandler} " +
        "where id = #{id}")
int updateResidentRegistrationNumber(@Param("id") Long id,
                                      @Param("residentRegistrationNumber") String residentRegistrationNumber);

// username만 바꾸는 경우 - id_no/phone 컬럼 자체를 SQL에서 아예 뺀다
@Update("update users set username = #{username} where id = #{id}")
int updateUsername(@Param("id") Long id, @Param("username") String username);
```

값을 바꿀 때 그 값이 Blind Index 대상 컬럼(id_no, phone)이라면 **`*_blind_idx` 컬럼도 같은 트랜잭션에서 함께 갱신**해야 한다 - 암호문만 바꾸고 blind index를 그대로 두면 그 행은 새 값으로 검색되지 않고 옛 값으로만 검색되는 상태가 된다.

```java
@Update("update users set phone = #{phone,typeHandler=com.xaan.demo.config.mybatis.UserPiiTypeHandler}, " +
        "phone_blind_idx = #{phoneBlindIndex} where id = #{id}")
int updatePhone(@Param("id") Long id, @Param("phone") String phone, @Param("phoneBlindIndex") String phoneBlindIndex);
```

```java
@Transactional
public void changePhone(Long userId, String newPhone) {
    String normalized = normalizePhone(newPhone);
    userMapper.updatePhone(userId, normalized, passwordService.computePhoneBlindIndex(normalized));
}
```

DEK/KEK 로테이션 이후의 재암호화 배치처럼 "이미 암호문인 값을 그대로 다시 저장"해야 하는 경우는 typeHandler를 아예 걸지 않는 `*Raw` 메서드를 따로 둔다(§8 체크리스트, [`ENCRYPTED_COLUMN_QUERY_GUIDE.md` §3-7](../demoApp/ENCRYPTED_COLUMN_QUERY_GUIDE.md#3-7-재암호화키-로테이션-배치---항상-raw-전용-메서드를-따로-둔다) 참고).

### 2-6. Delete

삭제 자체는 암호화 여부와 무관하게 일반 DELETE와 같다. 다만 다음을 함께 고려한다:

- **캐시 무효화**: 5장에서 다루는 `@Cacheable` 검색 결과에 삭제된 행이 남아있지 않도록 `@CacheEvict`를 건다.
- **감사 로그/소프트 삭제**: 삭제 이력을 남기더라도 복호화된 평문을 로그나 별도 테이블에 남기지 않는다 - 삭제 이력 테이블에 컬럼을 그대로 옮긴다면 암호문 그대로 옮긴다.

```java
@Delete("delete from users where id = #{id}")
int deleteById(Long id);
```

```java
@CacheEvict(value = "userSearchRaw", allEntries = true)
@Transactional
public void withdraw(Long userId) {
    userMapper.deleteById(userId);
}
```

---

## 3. 양방향 암호화 컬럼 조건 조회 - Blind Index

### 3-1. 왜 `WHERE phone = ?`가 안 되는가

AES-GCM은 매 암호화마다 `SecureRandom`으로 새 IV를 생성한다. 같은 평문 `"01012345678"`을 두 번 암호화해도 저장되는 암호문은 매번 다르므로, 암호문 컬럼에 `=`나 `LIKE`를 걸어도 애초에 매치될 값이 없다.

### 3-2. Blind Index 설계

키가 고정된 **결정적(deterministic) HMAC-SHA256**을 평문에 대해 계산해, 암호화된 컬럼 옆에 평문 컬럼으로 나란히 저장한다. 검색 시 검색어를 같은 방식으로 정규화한 뒤 HMAC을 계산해 그 컬럼을 `=`로 조회한다.

- **정확히 일치하는 값만** 찾을 수 있다(부분/`LIKE` 검색 불가 - HMAC 출력은 입력의 구조와 무관하다).
- 컬럼(필드)마다 별도의 키를 쓴다 - DEK/도메인과는 무관해서, DEK 로테이션이 blind index 값에 영향을 주지 않고 그 반대도 마찬가지다.
- Blind Index 키 자체는 로테이션을 지원하지 않는다 - 교체하려면 전체 재인덱싱(모든 행의 HMAC 재계산)이 필요한 별개의 작업이다.

### 3-3. Config

```java
@Bean
public BlindIndexKeyProvider blindIndexKeyProvider(VaultOperations vaultOperations,
        @Value("${vault.blind-index.base-path}") String basePath) {
    return new VaultBlindIndexKeyProvider(vaultOperations, basePath);
}

@Bean
public BlindIndexService phoneBlindIndexService(BlindIndexKeyProvider provider) {
    return BlindIndexService.forIndex("user-phone", provider);
}

@Bean
public BlindIndexService rrnBlindIndexService(BlindIndexKeyProvider provider) {
    return BlindIndexService.forIndex("user-rrn", provider);
}
```

### 3-4. DB 마이그레이션

```sql
ALTER TABLE ebiz.users ADD COLUMN IF NOT EXISTS phone VARCHAR(255);
ALTER TABLE ebiz.users ADD COLUMN IF NOT EXISTS phone_blind_idx VARCHAR(64);
ALTER TABLE ebiz.users ADD COLUMN IF NOT EXISTS id_no_blind_idx VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_users_phone_blind_idx ON ebiz.users (phone_blind_idx);
CREATE INDEX IF NOT EXISTS idx_users_id_no_blind_idx ON ebiz.users (id_no_blind_idx);
```

`phone_blind_idx`/`id_no_blind_idx`에 일반 B-tree 인덱스를 반드시 건다 - 그렇지 않으면 정확 일치 검색이 Seq Scan으로 떨어진다.

### 3-5. 저장 시 - 정규화와 함께 계산

```java
// UserService
private String normalizePhone(String phone) {
    return phone.replaceAll("[^0-9]", ""); // 하이픈 등 형식 문자 제거
}

public Long register(UserRegisterRequestDto dto) {
    String normalizedPhone = normalizePhone(dto.getPhone());
    User user = User.builder()
            .phone(normalizedPhone)
            .phoneBlindIndex(passwordService.computePhoneBlindIndex(normalizedPhone))
            .residentRegistrationNumber(dto.getResidentRegistrationNumber())
            .residentRegistrationNumberBlindIndex(passwordService.computeRrnBlindIndex(dto.getResidentRegistrationNumber()))
            .build();
    userMapper.insert(user);
    return user.getId();
}
```

```java
// PasswordService - BlindIndexService.compute()를 감싸기만 함
public String computePhoneBlindIndex(String phone) {
    return phoneBlindIndexService.compute(phone);
}
public String computeRrnBlindIndex(String residentRegistrationNumber) {
    return rrnBlindIndexService.compute(residentRegistrationNumber);
}
```

**정규화는 저장 시점과 검색 시점에 반드시 동일해야 한다** - `BlindIndexService.compute()` 자체는 정규화를 하지 않는다. 저장할 땐 하이픈을 제거하고 검색할 땐 하이픈이 남아 있으면 같은 번호인데도 HMAC이 달라져 **조용히 매칭에 실패한다**(에러 없음). demoApp은 정규화를 `UserService.normalizePhone()` 한 곳에서만 처리한다.

### 3-6. 검색 구현 - 동적 SQL로 여러 조건 조합

```java
@Select("""
        <script>
        select id, user_id, password, username, id_no, phone, id_no_blind_idx, phone_blind_idx
        from users
        <where>
            <if test="name != null and name != ''">
                and username like concat('%', #{name}, '%')
            </if>
            <if test="phoneBlindIndex != null and phoneBlindIndex != ''">
                and phone_blind_idx = #{phoneBlindIndex}
            </if>
            <if test="rrnBlindIndex != null and rrnBlindIndex != ''">
                and id_no_blind_idx = #{rrnBlindIndex}
            </if>
        </where>
        order by id desc
        </script>
        """)
List<User> search(@Param("name") String name,
                   @Param("phoneBlindIndex") String phoneBlindIndex,
                   @Param("rrnBlindIndex") String rrnBlindIndex);
```

```java
public List<UserResponseDto> search(String name, String phone, String residentRegistrationNumber) {
    String phoneBlindIndex = (phone == null || phone.isEmpty())
            ? null : passwordService.computePhoneBlindIndex(normalizePhone(phone));
    String rrnBlindIndex = (residentRegistrationNumber == null || residentRegistrationNumber.isEmpty())
            ? null : passwordService.computeRrnBlindIndex(residentRegistrationNumber);
    return userMapper.search(name, phoneBlindIndex, rrnBlindIndex).stream()
            .map(user -> new UserResponseDto(user,
                    passwordService.decryptUserPiiForDisplay(user.getResidentRegistrationNumber()),
                    passwordService.decryptUserPiiForDisplay(user.getPhone())))
            .collect(Collectors.toList());
}
```

암호화 대상이 아닌 컬럼(`username`)은 그냥 평문 `LIKE`로 부분 검색한다 - Blind Index가 필요 없다.

### 3-7. 기존 데이터 백필

이미 값이 있던 컬럼(`id_no`)에 Blind Index를 나중에 추가하면, 기존 행의 `id_no_blind_idx`는 `NULL`로 남는다. 백필 배치가 필요하다: 각 행의 `id_no`를 복호화 → `compute()`로 HMAC 계산 → `updateResidentRegistrationNumberBlindIndex(...)`로 저장. DEK 로테이션 재암호화 배치(`DekReencryptionService`)와 동일한 구조로 만들면 된다 - `CryptoException`(레거시/비정형 데이터)과 진짜 실패를 구분해서 집계하는 패턴까지 그대로 재사용 가능하다.

---

## 4. 단방향 암호화 컬럼 조건 조회

### 4-1. 원천적 제약 - "조건 조회" 자체가 성립하지 않는다

BCrypt는 매 호출마다 **자체적으로 랜덤 솔트를 생성**해 결과 문자열에 내장한다. 같은 원문 `"s3cret!"`을 두 번 해시해도 결과가 매번 다르다(`$2a$10$...` 뒤의 솔트+해시 부분이 매번 달라짐). 따라서:

- `WHERE password = #{bcryptHash(입력값)}` 방식은 **작동하지 않는다** - 저장된 해시와 입력을 해시한 결과가 우연히 일치할 수 없다.
- Blind Index처럼 "같은 입력이면 같은 출력"이 되는 결정적 방식이 아니므로, 3장의 패턴을 그대로 가져올 수도 없다.

**단방향(BCrypt) 컬럼은 SQL의 `WHERE` 조건으로 검증할 방법이 없다** - 이것이 이 방식을 쓰는 이유이기도 하다(DB가 유출돼도 원문은 물론, 값 자체로 무언가를 찾아낼 방법도 없어야 하는 게 목적).

### 4-2. 올바른 패턴 - "조건 조회"가 아니라 "다른 키로 조회 후 애플리케이션에서 검증"

로그인처럼 "이 비밀번호가 맞는가"를 확인해야 하는 요건은, `password` 컬럼을 조회 조건에 넣는 게 아니라 **다른 유일 키(`user_id`)로 행을 먼저 가져온 뒤, 애플리케이션 메모리에서 `matches()`로 비교**하는 방식으로 구현한다.

```java
// Mapper - password를 조건이 아니라 조회 결과로만 가져온다. PII 컬럼은 select하지 않는다(§2-3 참고)
@Select("select id, user_id, password, username from users where user_id = #{userId}")
Optional<User> findAuthByUserId(String userId);
```

```java
// Service
public boolean validateLogin(String userId, String rawPassword) {
    Optional<User> userOpt = userMapper.findAuthByUserId(userId);
    if (userOpt.isEmpty()) {
        return false;
    }
    return passwordService.validateUserPassword(rawPassword, userOpt.get().getPassword());
}
```

```java
// PasswordService - vault-crypto의 PasswordHasher에 위임
public boolean validateUserPassword(String rawPassword, String hashedPassword) {
    return passwordHasher.matches(rawPassword, hashedPassword); // 내부적으로 같은 솔트를 추출해 재해시 후 비교
}
```

```java
// Controller
@PostMapping("/login")
public String login(@ModelAttribute LoginRequestDto dto, HttpSession session) {
    if (!userService.validateLogin(dto.getUserId(), dto.getPassword())) {
        return "redirect:/login?error";
    }
    session.setAttribute("loginUser", dto.getUserId());
    return "redirect:/";
}
```

여기서 "조회 구현"의 핵심은 **`password` 컬럼을 WHERE에 넣지 않는 것**과 **필요 없는 다른 암호화 컬럼(id_no/phone)을 함께 select하지 않는 것** 두 가지다 - 후자를 지키지 않으면 로그인과 무관한 PII 컬럼의 ciphertext 문제가 로그인 자체를 막아버린다(비밀번호가 맞아도 로그인 실패).

### 4-3. "단방향 값으로 검색"이 정말 필요하다면

가끔 "이 비밀번호를 쓰는 계정을 찾아줘"처럼 단방향 컬럼 값 자체로 **역방향 검색**이 필요하다는 요건이 나올 수 있다. 결론부터 말하면 **BCrypt로는 원천적으로 불가능하고, 시도해서도 안 된다** - 그런 검색이 가능하다는 것 자체가 "같은 비밀번호를 쓰는 계정을 서로 찾아낼 수 있다"는 뜻이라 단방향 해시를 쓰는 목적(무차별 대입/레인보우 테이블 방어)과 정면으로 배치된다.

이런 요건이 실제로 있다면, 그건 "단방향 인증용 컬럼(BCrypt)에 조회 기능을 추가"하는 게 아니라 **3장의 Blind Index를 별도 필드로 새로 도입**해야 하는 문제다 - 예를 들어 "유출된 비밀번호 목록과 대조해 위험 계정을 찾는다"는 요건이라면, 인증용 `password`(BCrypt) 컬럼은 그대로 두고, 별도의 `password_blind_idx` 같은 컬럼에 (정규화 없이 원문 그대로에 대한) HMAC을 저장해 대조하는 방식을 검토한다. 다만 이 경우 인증 목적의 단방향 해시와 검색 목적의 결정적 인덱스가 같은 값에 대해 공존하게 되므로, 보안 요건(어떤 위협 모델을 방어하려는지) 검토가 선행되어야 하며 이 문서의 범위를 벗어난다 - 보안 담당자/설계자와 먼저 논의할 것을 권장한다.

### 4-4. 정리

| | 양방향 (id_no/phone) | 단방향 (password) |
|---|---|---|
| 조건 조회 방법 | Blind Index 컬럼에 `=` | **불가능** - 컬럼을 조건에 못 씀 |
| "조회 구현"의 의미 | 검색어의 HMAC을 계산해 WHERE에 사용 | 다른 키로 행을 가져온 뒤 애플리케이션에서 `matches()` |
| 필요 없는 조회에서 | select 자체는 해도 안전(단, 목록이면 §2-4처럼) | select 자체를 하지 않는 것을 권장(§4-2) |

---

## 5. Redis 캐싱을 고려한 앱 구현 방안

### 5-1. 원칙 - 캐시에는 절대 복호화된 값을 올리지 않는다

`@Cacheable`은 메서드의 **리턴값을 그대로 직렬화**해 캐시에 저장한다. 복호화된 DTO(평문 전화번호/주민등록번호 포함)를 리턴하는 메서드에 캐싱을 걸면, 그 순간 평문 개인정보가 Redis 서버에 그대로 올라간다. 항상 **암호문(ciphertext) 상태의 조회 결과만 캐싱**하고, 복호화는 캐시를 거친 뒤 매번 수행한다.

### 5-2. 캐싱 전용 빈으로 분리 - self-invocation 함정

`@Cacheable`은 Spring AOP 프록시를 통해서만 동작한다. 캐싱 대상 메서드를 **같은 클래스 안에서 `this.method(...)`처럼 직접 호출(self-invocation)**하면 프록시를 우회해서 캐싱이 **예외도 로그도 없이 조용히 동작하지 않는다.** demoApp에서 실제로 처음 이렇게 구현했다가 배포 직후 "캐시가 안 먹는다"는 걸 발견했다. 해결책은 캐싱 대상 메서드를 **별도의 `@Service` 빈**으로 분리해, 호출자가 항상 Spring이 관리하는 프록시를 거쳐 호출하도록 만드는 것이다.

```java
/**
 * 캐싱 대상은 반드시 raw(ciphertext) 조회여야 한다 - userMapper.search()가 id_no/phone을
 * 복호화하지 않고 그대로 반환하므로, Redis에 저장되는 값도 항상 ciphertext뿐이다.
 */
@Service
public class UserSearchCacheService {
    private final UserMapper userMapper;

    public UserSearchCacheService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Cacheable(value = "userSearchRaw",
            key = "(#name ?: '') + '|' + (#phoneBlindIndex ?: '') + '|' + (#rrnBlindIndex ?: '')")
    public List<User> search(String name, String phoneBlindIndex, String rrnBlindIndex) {
        return userMapper.search(name, phoneBlindIndex, rrnBlindIndex);
    }
}
```

```java
@Service
public class UserService {
    private final UserSearchCacheService userSearchCacheService; // 다른 빈을 통해서만 캐싱 메서드 호출
    private final PasswordService passwordService;

    public List<UserResponseDto> searchCached(String name, String phone, String residentRegistrationNumber) {
        String phoneBlindIndex = (phone == null || phone.isEmpty())
                ? null : passwordService.computePhoneBlindIndex(normalizePhone(phone));
        String rrnBlindIndex = (residentRegistrationNumber == null || residentRegistrationNumber.isEmpty())
                ? null : passwordService.computeRrnBlindIndex(residentRegistrationNumber);
        // 캐시 적중 여부와 무관하게 복호화는 항상 여기서 수행 - Redis에는 ciphertext만 존재
        return userSearchCacheService.search(name, phoneBlindIndex, rrnBlindIndex).stream()
                .map(user -> new UserResponseDto(user,
                        passwordService.decryptUserPiiForDisplay(user.getResidentRegistrationNumber()),
                        passwordService.decryptUserPiiForDisplay(user.getPhone())))
                .collect(Collectors.toList());
    }
}
```

### 5-3. 캐시 키 설계

캐시 키에도 평문을 남기지 않는다. 위 예시처럼 검색 조건을 조합할 때 **name은 평문(어차피 암호화 대상이 아님)이지만, phone/RRN은 Blind Index(HMAC) 값을 키에 사용**한다 - 원문 전화번호를 캐시 키 문자열로 그대로 쓰면 Redis의 키 목록 자체가 개인정보 노출 경로가 된다.

### 5-4. 캐시 값 직렬화

`@Cacheable`의 기본 직렬화는 JDK 직렬화다. 캐시에 담기는 엔티티는 `Serializable`을 구현해야 한다:

```java
public class User implements Serializable {
    // id_no/phone은 항상 ciphertext 상태로만 이 캐시에 담긴다
}
```

### 5-5. 캐시 무효화

검색 결과에 새 데이터가 반영되도록, 쓰기 경로(등록/수정/삭제)에 `@CacheEvict`를 건다. 신규 가입자는 어떤 검색 조합에든 걸릴 수 있으므로 `allEntries = true`로 전체 무효화한다.

```java
@CacheEvict(value = "userSearchRaw", allEntries = true)
@Transactional
public Long register(UserRegisterRequestDto dto) {
    // ...
}
```

이걸 빠뜨리면 방금 가입한 사용자가 캐시 TTL(아래 예시는 5분) 동안 검색 결과에 보이지 않는다.

### 5-6. TTL 설정

```properties
spring.cache.type=redis
spring.cache.redis.time-to-live=5m
```

### 5-7. 캐싱이 실제로 동작하는지 검증

Redis에 직접 접속(`redis-cli`)하지 않고도, DB 쪽 통계로 캐시 적중 여부를 확인할 수 있다: `pg_stat_user_tables.seq_scan`(해당 쿼리가 `Seq Scan`을 쓰는지 `EXPLAIN`으로 먼저 확인)을 캐싱 적용 전후로 비교해, 같은 검색 조건을 재조회했을 때 DB를 다시 타는지(`seq_scan` 증가 여부)를 본다. 새 검색어의 최초 조회는 DB를 타야 하고(+1), 동일 검색어의 재조회는 타지 않아야 한다(+0).

### 5-8. 전체 흐름

```
요청 → UserService.searchCached()
         ├─ blind index 계산 (평문 전화번호/RRN → HMAC)
         ↓
       UserSearchCacheService.search()  ← 별도 빈, @Cacheable 프록시가 여기서 걸림
         ├─ 캐시 적중: Redis에서 ciphertext 상태의 User 목록 반환
         └─ 캐시 미스: UserMapper.search() 실행 → 결과를 ciphertext 그대로 Redis에 저장 → 반환
         ↓
       UserService가 결과를 받아 행별 decryptUserPiiForDisplay() 수행  ← 캐시 적중 여부와 무관, 항상 실행
         ↓
       UserResponseDto (마스킹된 값만 응답에 포함)
```

---

## 6. 테스트 작성 방법 - Vault 없이 단위 테스트

`vault-crypto`는 실제 Vault 서버 없이도 단위 테스트를 작성할 수 있도록 테스트 전용 생성자를 제공한다.

- `KekService(byte[] rawKekBytes)` - 단일 키(버전 1)만 필요한 테스트용 생성자
- `BlindIndexService.withKey(byte[])` - provider 없이 키를 직접 주입
- `DekProvider`는 인터페이스이므로 인메모리 구현체로 대체 가능

```java
class PasswordServiceTest {

    @Test
    void blindIndexIsDeterministicAndFieldsAreIndependent() {
        PasswordService passwordService = newPasswordService(
                newCryptoService("board", (byte) 1), newCryptoService("user-pii", (byte) 2));

        assertThat(passwordService.computePhoneBlindIndex("01012345678"))
                .isEqualTo(passwordService.computePhoneBlindIndex("01012345678")); // 결정적
        assertThat(passwordService.computePhoneBlindIndex("01012345678"))
                .isNotEqualTo(passwordService.computeRrnBlindIndex("01012345678")); // 필드별 독립 키
    }

    private PasswordService newPasswordService(EnvelopeCryptoService board, EnvelopeCryptoService userPii) {
        return new PasswordService(board, userPii,
                BlindIndexService.withKey(randomBytes(32)),
                BlindIndexService.withKey(randomBytes(32)));
    }

    private EnvelopeCryptoService newCryptoService(String domain, byte domainCode) {
        KekService kek = new KekService(randomBytes(32));                 // Vault 없이 단일 키
        InMemoryDekProvider dekProvider = new InMemoryDekProvider();       // 아래 참고
        byte[] plaintextDek = randomBytes(32);
        dekProvider.store(domain, new WrappedDek(domain, 1, kek.wrap(plaintextDek)), 1);
        return EnvelopeCryptoService.forDomain(domainCode, domain, kek, dekProvider);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /** DekProvider 인터페이스를 구현한 최소 인메모리 스텁 - VaultDekProvider 대신 사용 */
    private static final class InMemoryDekProvider implements DekProvider {
        private final Map<String, List<WrappedDek>> versionsByDomain = new HashMap<>();
        private final Map<String, Integer> currentVersionByDomain = new HashMap<>();

        public List<WrappedDek> loadAll(String domain) { return versionsByDomain.getOrDefault(domain, List.of()); }
        public int loadCurrentVersion(String domain) { return currentVersionByDomain.get(domain); }
        public void store(String domain, WrappedDek v, int cur) {
            versionsByDomain.computeIfAbsent(domain, d -> new ArrayList<>()).add(v);
            currentVersionByDomain.put(domain, cur);
        }
        public void retire(String domain, int version) {
            versionsByDomain.get(domain).removeIf(w -> w.version() == version);
        }
    }
}
```

이 패턴으로 검증할 만한 것들:
- `validate()`가 올바른/틀린 원문을 정확히 구분하는지
- 레거시/비정형 데이터(이 라이브러리 포맷이 아닌 문자열)를 `validate()`/`decryptUserPiiForDisplay()`에 넣었을 때 예외 대신 `false`/대체 문자열을 반환하는지 - 실제 운영 장애를 재현하는 회귀 테스트로 유효하다
- Blind Index가 결정적인지, 필드별로 독립적인지
- `null`/빈 문자열 입력이 그대로 통과하는지

MyBatis TypeHandler 자체(`EnvelopeCryptoTypeHandler`)를 검증하려면 Mock이 아니라 **실제 H2 인메모리 JDBC 커넥션**으로 검증하는 편이 낫다 - `vault-crypto`의 `EnvelopeCryptoTypeHandlerTest`가 이 패턴이다: 원본 컬럼에는 암호문이 저장되고, 핸들러를 통해 읽으면 평문이 복원되는지를 실제 SQL 왕복으로 확인한다.

---

## 7. 로깅 · 마스킹 · 트랜잭션 주의사항

- **복호화된 평문을 로그에 남기지 않는다.** `decryptUserPiiForDisplay()`처럼 실패를 로깅할 때도 `e.getMessage()`(에러 메시지)만 남기고 복호화 시도 중이던 값 자체는 남기지 않는다.
- **응답에 노출할 때도 마스킹한다.** `UserResponseDto`는 복호화된 전화번호/주민등록번호를 그대로 내려주지 않고 일부만 노출한다(전화번호는 앞 3자리, 주민등록번호는 3~5번째 자리만 남기고 나머지 `*`). 목록 화면처럼 "본인 확인" 목적이 아닌 조회는 항상 이렇게 마스킹된 형태로만 노출하는 것을 기본값으로 삼는다.
- **암호문 + Blind Index + 관련 평문 컬럼은 하나의 트랜잭션/SQL로 저장한다.** INSERT 하나로 묶는 게 가장 안전하고, 부득이하게 나눠야 한다면 `@Transactional`로 묶어 부분 실패(암호문만 저장되고 Blind Index는 누락되는 등)를 방지한다.
- **재암호화/키 로테이션 배치는 `CryptoException`과 그 외 `RuntimeException`을 반드시 구분해서 집계한다.** 전자는 "이 라이브러리 포맷이 아닌 행"(정상적으로 건너뛰어야 함), 후자만 진짜 조사가 필요한 실패다 - demoApp은 이 구분을 놓쳐서 4만 건 이상의 오탐 에러 로그가 찍힌 뒤 고친 실전 사례가 있다(자세한 내용은 이 저장소의 `README.md` "DEK 로테이션 이후 - 기존 행 재암호화 배치" 참고).

---

## 8. 신규 암호화 컬럼 추가 체크리스트

1. **성격 판단**: 원문이 다시 필요한가? → 필요 없음: BCrypt(`PasswordHasher`). 필요함: KEK-DEK 봉투 암호화(`EnvelopeCryptoService`).
2. **레거시 데이터 여부**: 이 컬럼이 있는 테이블에 이 라이브러리 도입 이전 데이터가 섞여 있는가? → 있으면 TypeHandler는 쓰기 경로에만, 읽기는 명시적 `decrypt()`/`validate()` 호출로.
3. **도메인 분리**: 새 도메인이 필요한가, 기존 도메인(`user-pii` 등)에 얹을 것인가? 새 도메인이면 `domainCode`를 기존 값과 겹치지 않게 배정, Vault에 해당 도메인 DEK 시크릿 생성.
4. **검색 요건 (양방향 컬럼만 해당)**: 정확 일치 검색이 필요한가? → 필요하면 Blind Index 컬럼(`*_blind_idx`) 추가, Vault에 필드별 HMAC 키 생성, DB 마이그레이션에 컬럼+인덱스 함께.
5. **불필요한 조회 배제**: 이 컬럼이 필요 없는 조회 경로(로그인 등)가 있는가? → 그 경로는 이 컬럼을 아예 select하지 않는 전용 메서드로 분리.
6. **목록 조회 대비**: 이 컬럼을 여러 행과 함께 목록으로 보여줄 일이 있는가? → raw 조회 + 행별 복호화(fallback) 패턴 적용.
7. **캐싱 계획**: 이 컬럼이 포함된 조회 결과를 캐싱할 계획이 있는가? → raw만 캐싱, 복호화는 캐시 밖에서, 캐싱 메서드는 별도 빈.
8. **UPDATE 부분 갱신**: "값이 바뀌지 않는 경우"가 존재하는가? → 그 컬럼을 건드리지 않는 별도 UPDATE 메서드로 분리. Blind Index 대상이면 값이 바뀔 때 그 컬럼도 함께 갱신.
9. **재암호화/로테이션 대비**: 향후 DEK 로테이션 대상인가? → `*Raw` 메서드 쌍(조회+저장) 추가.
10. **기존 데이터 백필**: 컬럼/Blind Index를 기존에 값이 있던 테이블에 추가하는가? → 백필 배치 계획.
11. **테스트**: `withKey`/`InMemoryDekProvider` 패턴으로 Vault 없이 단위 테스트 작성.
12. **문서화**: 이 가이드의 표/체크리스트에 신규 컬럼을 추가 반영.

---

## 9. 흔한 실수 요약

| # | 실수 | 증상 |
|---|------|------|
| 1 | 레거시 데이터 있는 컬럼의 읽기 경로에 typeHandler를 검 | 목록/상세 조회가 `CryptoException`으로 500 |
| 2 | 바뀌지 않은 암호문 값을 UPDATE의 typeHandler 파라미터로 다시 흘림 | 데이터가 조용히 이중 암호화되어 나중에 복호화 불가 |
| 3 | 로그인처럼 암호화 컬럼이 필요 없는 조회에서 그 컬럼까지 select | 관련 없는 계정의 PII 문제가 그 계정 로그인을 막음 |
| 4 | 목록 조회에 typeHandler를 읽기 경로에 걸어 한 번에 여러 행을 복호화 | 행 하나의 ciphertext 문제로 전체 목록이 500 |
| 5 | `@Cacheable` 메서드를 같은 클래스 안에서 `this`로 직접 호출 | 예외 없이 캐싱이 조용히 동작하지 않음 |
| 6 | BCrypt(단방향) 컬럼을 조건 조회하려고 시도 | 애초에 매치가 안 됨 - 같은 원문도 해시가 매번 다름 |
| 7 | Blind Index 저장/검색 시 정규화 방식이 다름 | 같은 값인데도 조용히 검색 실패(에러 없음) |
| 8 | 재암호화 배치에서 `CryptoException`(레거시)과 진짜 실패를 구분 안 함 | 정상 상황이 대량 오류 로그로 오탐 |
| 9 | 커스텀 TypeHandler를 `BaseTypeHandler<String>`으로 직접 구현 | 앱의 모든 `String` 컬럼이 조용히 암호화되는 사고 |

상세 사례와 원인 분석은 [`ENCRYPTED_COLUMN_QUERY_GUIDE.md` §5](../demoApp/ENCRYPTED_COLUMN_QUERY_GUIDE.md#5-흔한-실수-top-5-전부-실제로-겪은-것)와 `vault-crypto/README.md`의 Release History(v0.0.10, v0.0.9, v0.0.8)를 참고하세요.
