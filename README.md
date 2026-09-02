# vault-crypto

HashiCorp Vault 기반 KEK-DEK 봉투 암호화(Envelope Encryption) 라이브러리 for Spring Boot

## 개요

`vault-crypto`는 HashiCorp Vault에 저장된 KEK(Key Encryption Key)로 서비스 도메인별 DEK(Data Encryption Key)를 wrap/unwrap하고, 각 도메인의 DEK를 메모리에 캐시하여 AES-256 GCM으로 데이터를 암/복호화하는 Spring Boot 라이브러리입니다.

### 주요 특징

- **KEK-DEK 봉투 암호화**: Vault의 KEK는 데이터를 직접 암호화하지 않고 도메인별 DEK를 wrap하는 용도로만 사용
- **도메인 격리**: 서비스 도메인(예: `board`, `user-pii`)마다 독립된 DEK를 사용해 한 도메인의 키 유출이 다른 도메인으로 번지지 않음
- **성능**: DEK는 앱 기동 시 1회 unwrap되어 메모리에 캐시되므로, 이후 암/복호화 호출은 Vault 네트워크 호출 없이 로컬에서 수행됨
- **키 로테이션 지원**: 암호문에 `domainCode`+`keyVersion` 헤더를, wrapped DEK에 `kekVersion` 헤더를 포함해 DEK/KEK를 각각 교체한 뒤에도 이전 버전으로 암호화(wrap)된 데이터를 계속 복호화(unwrap) 가능 — 상세 절차는 이 라이브러리를 사용하는 demoApp 저장소의 `KEY_ROTATION_RUNBOOK.md` 참고
- **AES-256 GCM**: 인증된 암호화(Authenticated Encryption) 지원
- **Spring 통합**: `VaultOperations`를 통한 Spring Cloud Vault 연동
- **커스텀 예외**: `CryptoException`, `KeyLoadingException`으로 세밀한 오류 처리

### 아키텍처

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Your Application                             │
│              (BoardService, UserService, ... 도메인별 서비스)          │
├──────────────────────────────────────────────────────────────────────┤
│                       EnvelopeCryptoService (도메인당 1개)             │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐            │
│  │ encrypt()  │  │ decrypt()  │  │ validate()            │            │
│  └────────────┘  └────────────┘  └──────────────────────┘            │
│                              │                                        │
│                     DomainKeyRing (unwrap된 DEK를 버전별로 메모리 캐시) │
├──────────────────────────────────────────────────────────────────────┤
│  KekService (버전별 KEK 보관, wrap/unwrap) │  DekProvider (wrapped DEK 저장/조회) │
│         KekProvider (versioned)            │  VaultDekProvider (versioned)      │
├──────────────────────────────────────────────────────────────────────┤
│                        Spring Cloud Vault                             │
│                    (VaultOperations / VaultTemplate)                  │
├──────────────────────────────────────────────────────────────────────┤
│                       HashiCorp Vault Server                          │
│    kv-v2: kek (버전별 마스터 키) + dek/{domain} (wrapped DEK, 버전별)  │
└──────────────────────────────────────────────────────────────────────┘
```

## 프로젝트 구조

```
vault-crypto/
├── src/main/java/com/xaan/vault/crypto/
│   ├── CryptoException.java              # 암호화 관련 기본 예외
│   ├── KeyLoadingException.java          # Vault 키 로딩 예외
│   ├── PasswordHasher.java               # BCrypt 단방향 해시 (외부 키 불필요, Vault 무관)
│   └── envelope/
│       ├── AesGcmCodec.java              # 공용 AES-256-GCM 바이트 코덱 (내부용)
│       ├── KekService.java               # 버전별 KEK 보관 + DEK wrap/unwrap
│       ├── KekProvider.java              # 버전별 KEK 저장소 인터페이스
│       ├── VaultKekProvider.java         # Vault KV-v2 기반 KekProvider 구현체
│       ├── KekRotationSupport.java       # KEK 로테이션(신규 버전 발급 + DEK 재wrap) 유틸
│       ├── WrappedDek.java               # (domain, version, wrappedBytes) 레코드
│       ├── DekProvider.java              # wrapped DEK 저장소 인터페이스
│       ├── VaultDekProvider.java         # Vault KV-v2 기반 DekProvider 구현체
│       ├── DomainKeyRing.java            # 도메인별 unwrap된 DEK 메모리 캐시
│       ├── EnvelopeCryptoService.java    # 도메인 스코프 encrypt/decrypt/validate
│       └── DekRotationSupport.java       # DEK 로테이션(신규 버전 발급) 유틸
│   ├── blindindex/
│   │   ├── BlindIndexKeyProvider.java    # 필드별 HMAC 키 저장소 인터페이스 (버전 없음)
│   │   ├── VaultBlindIndexKeyProvider.java # Vault KV-v2 기반 BlindIndexKeyProvider 구현체
│   │   └── BlindIndexService.java        # HMAC-SHA256 기반 결정적 blind index 계산
│   └── mybatis/
│       └── EnvelopeCryptoTypeHandler.java # MyBatis TypeHandler - 컬럼 단위 투명 암/복호화
├── build.gradle                   # Gradle 빌드 설정
├── settings.gradle                # 프로젝트 설정
├── README.md
├── VAULT_CRYPTO_DEV_GUIDE.md      # Spring Boot+MyBatis+Redis 환경 종합 개발 가이드 (demoApp users 테이블 예제)
└── VAULT_CRYPTO_DEV_GUIDE.pptx    # 위 가이드를 슬라이드로 정리한 발표 자료
```

## 요구사항

| 항목 | 버전 |
|------|------|
| Java | 17 이상 |
| Spring Cloud Vault | 3.x |
| HashiCorp Vault | kv-v2 백엔드 |
| Gradle | 8.x |

## 빌드

### Windows

```bat
set JAVA_HOME=C:\SW\jdk-17.0.15
set PATH=%JAVA_HOME%\bin;C:\SW\gradle-8.14.5\bin;%PATH%

gradle.bat clean build publishToMavenLocal
```

### Linux

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

./gradlew clean build publishToMavenLocal
```

빌드된 JAR는 `~/.m2/repository/com/xaan/vault-crypto/0.0.10/`에 설치됩니다.

## 의존성 추가

### Gradle (Spring Boot 프로젝트)

```groovy
plugins {
    id 'org.springframework.boot' version '3.4.0'
    id 'io.spring.dependency-management' version '1.1.6'
}

ext {
    set('springCloudVersion', '2024.0.0')
}

repositories {
    mavenLocal()    // vault-crypto는 로컬 Maven에서 로드
    mavenCentral()
}

dependencies {
    // vault-crypto 라이브러리
    implementation 'com.xaan:vault-crypto:0.0.10'

    // Spring Cloud Vault (필수 의존성)
    implementation 'org.springframework.cloud:spring-cloud-starter-vault-config'
}

dependencyManagement {
    imports {
        mavenBom "org.springframework.cloud:spring-cloud-dependencies:${springCloudVersion}"
    }
}
```

### Maven

```xml
<dependency>
    <groupId>com.xaan</groupId>
    <artifactId>vault-crypto</artifactId>
    <version>0.0.10</version>
</dependency>
```

## Vault 설정

### Step 1: Vault kv-v2 백엔드 활성화

```bash
vault secrets enable -path=ebiz_service kv-v2
```

### Step 2: KEK(마스터 키) 저장

KEK도 DEK와 동일하게 버전별 필드 + `current-version` 포인터로 저장합니다(로테이션 시 이전 버전도 계속 읽을 수 있어야 하므로):

```bash
vault kv put -mount=ebiz_service ebiz_db/kek \
  kek-v1="<Base64URL 인코딩된 32바이트 랜덤 키>" \
  current-version="1"
```

### Step 3: 도메인별 DEK 생성 및 저장 (KEK로 wrap된 상태로 저장)

DEK는 애플리케이션이 임의로 생성해 KEK로 wrap한 뒤 저장해야 하므로, 단순 `vault kv put`만으로는 만들 수 없습니다. 값 계산은 `KekService.wrap(byte[])`를 그대로 쓰거나, 별도 부트스트랩 스크립트로 생성합니다(demoApp의 `bootstrap_kek_dek.py` 참고). `wrap()`의 출력에는 이미 `kekVersion(1B)` 헤더가 포함되어 있으므로 별도로 버전을 더 붙일 필요는 없습니다. 저장 형태는 도메인당 시크릿 1개, DEK 버전별 필드:

```bash
vault kv put -mount=ebiz_service ebiz_db/dek/board \
  dek-v1="<Base64URL(kekVersion+IV+ciphertext+tag), KEK로 wrap된 DEK>" \
  current-version="1"

vault kv put -mount=ebiz_service ebiz_db/dek/user-pii \
  dek-v1="<Base64URL(kekVersion+IV+ciphertext+tag), KEK로 wrap된 DEK>" \
  current-version="1"
```

### Step 4: 키 저장 확인

```bash
vault kv get -mount=ebiz_service ebiz_db/kek
vault kv get -mount=ebiz_service ebiz_db/dek/board
```

### Step 5: Spring Boot application.properties

```properties
# Vault 서버 연결 설정
spring.cloud.vault.uri=${VAULT_URI:http://192.168.2.57:8200}
spring.cloud.vault.token=${VAULT_TOKEN:hvs.YOUR_TOKEN_HERE}
spring.cloud.vault.fail-fast=true

# KEK / DEK 경로 (kv-v2이므로 {mount}/data/{path} 형식)
vault.kek.path=${VAULT_KEK_PATH:ebiz_service/data/ebiz_db/kek}
vault.dek.base-path=${VAULT_DEK_BASE_PATH:ebiz_service/data/ebiz_db/dek}
```

> **참고**: 경로 형식은 `{mount}/data/{secret-path}`입니다. kv-v2에서 `data`는 Vault API가 자동으로 삽입하는 경로 세그먼트입니다.

## 사용 가이드

vault-crypto는 성격이 다른 두 종류의 암호화를 제공합니다. 다루는 값이 "원문을 다시 볼 필요가 있는가"에 따라 골라 쓰면 됩니다.

| | **단방향 (One-way) — BCrypt** | **양방향 (Two-way) — KEK-DEK 봉투 암호화** |
|---|---|---|
| 제공 클래스 | `PasswordHasher` | `EnvelopeCryptoService` |
| 원문 복구 | 불가능 (해시만 비교) | 가능 (`decrypt()`로 원문 복원) |
| 대표 용도 | 로그인 계정 비밀번호 | 게시글 비밀번호, 주민등록번호 등 개인정보 |
| 키 관리 | 불필요 (솔트를 자체 생성해 결과 문자열에 내장) | 필요 (Vault의 KEK가 도메인별 DEK를 wrap) |
| Vault 의존성 | 없음 | 있음 (앱 기동 시 1회 로드, 이후 요청은 로컬에서만 처리) |
| 저장 형식 예 | `$2a$10$N9qo8uLOickgx2ZMRZoMy...` | `AQHx9F3...`(Base64, `domainCode+keyVersion+IV+ciphertext+tag`) |

vault-crypto 자체는 JPA/MyBatis 어느 쪽에도 의존하지 않습니다 — `EnvelopeCryptoService`/`PasswordHasher`는 순수 Java 객체를 encrypt/decrypt/hash할 뿐이고, 영속성 계층과 어떻게 엮을지는 소비 프로젝트가 정합니다. 아래 1·2절은 두 방식 공통이고, 3절(JPA)·4절(MyBatis)에서 각 영속성 기술에 실제로 통합하는 방법을 다룹니다.

> **더 실전에 가까운 종합 가이드가 필요하다면**: [`VAULT_CRYPTO_DEV_GUIDE.md`](VAULT_CRYPTO_DEV_GUIDE.md) - Spring Boot + MyBatis + Redis 환경에서 이 라이브러리로 DB 컬럼 암호화를 처음부터 구축하는 절차를 다룹니다. 양방향/단방향 컬럼을 모두 가진 실제 테이블(demoApp의 `users`)을 예제로, 의존성·Vault 설정부터 CRUD, Blind Index 검색, 단방향 컬럼 조회, Redis 캐싱(self-invocation 함정 포함), Vault 없는 단위 테스트 작성법까지 정리했습니다. 같은 내용을 발표 자료로 정리한 [`VAULT_CRYPTO_DEV_GUIDE.pptx`](VAULT_CRYPTO_DEV_GUIDE.pptx)도 있습니다.

---

### 1. 단방향 암호화 — BCrypt로 로그인 비밀번호 다루기

"맞는지 검증"만 하면 되고 원문 복구가 필요 없는 값(로그인 비밀번호)은 `PasswordHasher`를 씁니다. BCrypt는 솔트를 자체 생성해 결과 문자열에 내장하므로 외부 키가 필요 없고, 따라서 Vault 설정이나 KEK/DEK 부트스트랩 없이 바로 쓸 수 있습니다. 결과가 그냥 `String` 컬럼 하나이므로 JPA 엔티티 필드든 MyBatis Mapper 파라미터든 동일하게 다루면 됩니다 — 아래는 vault-crypto를 그대로 감싸는 얇은 서비스 예제입니다:

```java
import com.xaan.vault.crypto.PasswordHasher;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    public String hashUserPassword(String rawPassword) {
        return passwordHasher.hash(rawPassword); // 매 호출마다 다른 솔트 -> 다른 결과 문자열
    }

    public boolean validateUserPassword(String rawPassword, String hashedPassword) {
        return passwordHasher.matches(rawPassword, hashedPassword);
    }
}
```

가입/로그인 흐름에서는 영속성 기술과 무관하게 이 두 메서드만 호출하면 됩니다(demoApp의 실제 코드 — `PasswordService.hashUserPassword`/`validateUserPassword`, MyBatis 기반):

```java
// 가입 - 비밀번호는 해시로 변환한 뒤에만 저장 대상 엔티티/객체에 담는다
String hashedPassword = passwordService.hashUserPassword(dto.getPassword());
User user = User.builder()
        .userId(dto.getUserId())
        .password(hashedPassword)
        // ...
        .build();
userMapper.insert(user); // 또는 JPA라면 userRepository.save(user)

// 로그인 - 저장된 해시와 비교만 한다. id_no/phone 같은 PII 컬럼은 로그인에 필요 없으므로
// 애초에 조회조차 하지 않는다(불필요한 컬럼을 복호화 경로에 태우지 않기 위해).
public boolean validateLogin(String userId, String rawPassword) {
    Optional<User> userOpt = userMapper.findAuthByUserId(userId); // password만 있는 전용 조회
    return userOpt.isPresent() && passwordService.validateUserPassword(rawPassword, userOpt.get().getPassword());
}
```

`decrypt()`에 해당하는 메서드가 아예 없다는 점이 핵심입니다 — DB가 통째로 유출되어도 저장된 해시에서 원문 비밀번호를 복원할 방법이 없습니다.

---

### 2. 양방향 암호화 — 공통 Config: 도메인별 `EnvelopeCryptoService` 빈 구성

원문이 나중에 다시 필요한 값(개인정보 조회, 비밀번호 확인 화면 등)은 `EnvelopeCryptoService`를 씁니다. 앞의 [Vault 설정](#vault-설정) 단계(KEK/DEK를 Vault에 저장)가 먼저 끝나 있어야 합니다. 이 Config는 JPA/MyBatis 어느 쪽을 쓰든 완전히 동일합니다 — `EnvelopeCryptoService`는 영속성 계층을 전혀 모르는 순수 암/복호화 빈이기 때문입니다. 아래는 demoApp의 실제 `CryptoConfig`입니다(`board`, `user-pii` 두 도메인 + Blind Index 빈까지 한 곳에서 구성):

```java
package com.xaan.demo.config;

import com.xaan.vault.crypto.blindindex.BlindIndexKeyProvider;
import com.xaan.vault.crypto.blindindex.BlindIndexService;
import com.xaan.vault.crypto.blindindex.VaultBlindIndexKeyProvider;
import com.xaan.vault.crypto.envelope.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.core.VaultOperations;

@Configuration
public class CryptoConfig {

    public static final byte BOARD_DOMAIN_CODE = 1;
    public static final byte USER_PII_DOMAIN_CODE = 2;

    @Bean
    public KekProvider kekProvider(
            VaultOperations vaultOperations,
            @Value("${vault.kek.path:ebiz_service/data/ebiz_db/kek}") String kekPath) {
        return new VaultKekProvider(vaultOperations, kekPath);
    }

    @Bean
    public KekService kekService(KekProvider kekProvider) {
        return KekService.load(kekProvider);
    }

    @Bean
    public DekProvider dekProvider(
            VaultOperations vaultOperations,
            @Value("${vault.dek.base-path:ebiz_service/data/ebiz_db/dek}") String dekBasePath) {
        return new VaultDekProvider(vaultOperations, dekBasePath);
    }

    // 서비스 도메인마다 빈을 하나씩 둔다. domainCode는 도메인마다 고유한 1바이트 값.
    @Bean
    public EnvelopeCryptoService boardCryptoService(KekService kekService, DekProvider dekProvider) {
        return EnvelopeCryptoService.forDomain(BOARD_DOMAIN_CODE, "board", kekService, dekProvider);
    }

    @Bean
    public EnvelopeCryptoService userPiiCryptoService(KekService kekService, DekProvider dekProvider) {
        return EnvelopeCryptoService.forDomain(USER_PII_DOMAIN_CODE, "user-pii", kekService, dekProvider);
    }

    // 전화번호/주민등록번호 검색용 - 필드마다 독립된 HMAC 키를 쓰므로 도메인 코드 없이 문자열 이름으로 구분
    @Bean
    public BlindIndexKeyProvider blindIndexKeyProvider(
            VaultOperations vaultOperations,
            @Value("${vault.blind-index.base-path:ebiz_service/data/ebiz_db/blind-index}") String basePath) {
        return new VaultBlindIndexKeyProvider(vaultOperations, basePath);
    }

    @Bean
    public BlindIndexService phoneBlindIndexService(BlindIndexKeyProvider blindIndexKeyProvider) {
        return BlindIndexService.forIndex("user-phone", blindIndexKeyProvider);
    }

    @Bean
    public BlindIndexService rrnBlindIndexService(BlindIndexKeyProvider blindIndexKeyProvider) {
        return BlindIndexService.forIndex("user-rrn", blindIndexKeyProvider);
    }
}
```

`EnvelopeCryptoService.forDomain(...)`이 호출되는 시점(빈 생성 시, 즉 앱 기동 시)에 KEK로 해당 도메인의 DEK를 1회 unwrap해서 메모리에 캐시합니다. 이후 `encrypt()`/`decrypt()`/`validate()` 호출은 Vault를 다시 호출하지 않습니다. 이 빈들을 이제부터 JPA(3절) 또는 MyBatis(4절) 계층에서 그대로 주입받아 씁니다.

---

### 3. JPA 프로젝트에서 사용하기

> **참고**: 아래 예제는 참고용 가상 예제입니다. demoApp은 과거 Spring Data JPA를 사용하다가 MyBatis 3.5.16으로 완전히 마이그레이션되었고, 현재 코드베이스에는 `@Entity`/`JpaRepository` 등 JPA 관련 코드가 전혀 남아 있지 않습니다(README 변경 이력 참고). 즉 이 절은 demoApp의 실제 코드가 아니라, Spring Data JPA 프로젝트에 vault-crypto를 통합하는 일반적인 패턴을 보여주기 위한 예시입니다. 실제 프로덕션에서 검증된 사례가 필요하면 4절(MyBatis, demoApp `users` 테이블 실제 구현)을 참고하세요.

#### 3-1. Service에서 직접 encrypt/decrypt 호출하기

가장 단순한 방법은 Service 계층에서 `EnvelopeCryptoService`를 직접 호출하고, 엔티티/Repository는 이미 암호화된 문자열을 평범한 컬럼처럼 다루게 하는 것입니다.

```java
@Entity
@Table(name = "board")
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private String content;
    private String password; // 항상 암호문 상태로 저장 - 엔티티는 암/복호화를 모른다

    protected Post() {}

    public Post(String title, String content, String encryptedPassword) {
        this.title = title;
        this.content = content;
        this.password = encryptedPassword;
    }

    public Long getId() { return id; }
    public String getContent() { return content; }
    public String getPassword() { return password; }
}

public interface PostRepository extends JpaRepository<Post, Long> {}
```

```java
@Service
public class PasswordService {

    private final EnvelopeCryptoService boardCryptoService;

    public PasswordService(@Qualifier("boardCryptoService") EnvelopeCryptoService boardCryptoService) {
        this.boardCryptoService = boardCryptoService;
    }

    public String encryptBoardPassword(String password) {
        return boardCryptoService.encrypt(password);
    }

    public boolean validateBoardPassword(String rawPassword, String encryptedPassword) {
        return boardCryptoService.validate(rawPassword, encryptedPassword);
    }
}
```

```java
@RestController
@RequestMapping("/api/posts")
public class PostController {

    private final PasswordService passwordService;
    private final PostRepository postRepository;

    public PostController(PasswordService passwordService, PostRepository postRepository) {
        this.passwordService = passwordService;
        this.postRepository = postRepository;
    }

    @PostMapping
    public ResponseEntity<Long> save(@RequestBody SaveRequest req) {
        String encryptedPassword = passwordService.encryptBoardPassword(req.password());
        Post post = new Post(req.title(), req.content(), encryptedPassword);
        return ResponseEntity.ok(postRepository.save(post).getId());
    }

    @PostMapping("/{id}/view")
    public ResponseEntity<String> view(@PathVariable Long id, @RequestBody ViewRequest req) {
        Post post = postRepository.findById(id).orElseThrow();
        if (!passwordService.validateBoardPassword(req.password(), post.getPassword())) {
            return ResponseEntity.status(403).body("비밀번호가 일치하지 않습니다");
        }
        return ResponseEntity.ok(post.getContent());
    }

    public record SaveRequest(String title, String content, String password) {}
    public record ViewRequest(String password) {}
}
```

단순히 "맞는지"만 확인하면 되는 경우엔 `decrypt()` 대신 `validate()`를 쓰는 편이 낫습니다 — 상수 시간 비교로 Timing Attack을 막아주기 때문입니다.

#### 3-2. `AttributeConverter`로 최소 변경 통합하기

컬럼 단위로 암/복호화를 숨기고 싶다면 JPA의 `AttributeConverter`를 씁니다 — MyBatis의 `EnvelopeCryptoTypeHandler`(4절)와 동일한 발상이지만, **vault-crypto는 MyBatis용 TypeHandler만 제공**하고 JPA용 Converter는 제공하지 않으므로 소비 프로젝트가 직접 작성해야 합니다:

```java
import com.xaan.vault.crypto.envelope.EnvelopeCryptoService;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

// EnvelopeCryptoTypeHandler와 동일한 패턴: EnvelopeCryptoService 하나에 고정된 컬럼 하나만 담당하는 얇은 래퍼.
@Component
@Converter
public class BoardPasswordConverter implements AttributeConverter<String, String> {

    private final EnvelopeCryptoService boardCryptoService;

    public BoardPasswordConverter(@Qualifier("boardCryptoService") EnvelopeCryptoService boardCryptoService) {
        this.boardCryptoService = boardCryptoService;
    }

    @Override
    public String convertToDatabaseColumn(String plainText) {
        return plainText == null ? null : boardCryptoService.encrypt(plainText);
    }

    @Override
    public String convertToEntityAttribute(String encryptedText) {
        return encryptedText == null ? null : boardCryptoService.decrypt(encryptedText);
    }
}
```

```java
@Entity
@Table(name = "board")
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private String content;

    @Convert(converter = BoardPasswordConverter.class)
    private String password; // 엔티티는 항상 평문만 다룬다 - 변환은 컨버터가 전담

    // ...
}
```

두 가지 주의할 점이 있습니다:

1. **`@Component`로 Spring 빈으로 등록해야만 생성자로 `EnvelopeCryptoService`를 주입받을 수 있습니다.** JPA가 컨버터를 기본 생성자로 직접 만들면 DI가 불가능합니다 — Spring Boot의 Hibernate 자동 설정이 `hibernate.resource.beans.container`를 `SpringBeanContainer`로 구성해 주는 것에 의존하는데, Spring Boot 2.x 이상에서는 기본으로 활성화되어 있습니다.
2. **`@Converter(autoApply = true)`는 쓰지 마세요.** 이 라이브러리의 MyBatis `EnvelopeCryptoTypeHandler`가 v0.0.9에서 겪었던 것과 정확히 같은 함정입니다 — `autoApply = true`는 명시적으로 지정하지 않은 모든 `String` 타입 필드에까지 컨버터가 조용히 적용될 수 있습니다(v0.0.10 릴리스 노트 참고). 반드시 `@Convert(converter = ...)`로 필드마다 명시적으로 지정하세요.

`PostRepository`/`PostService`/`PostController`는 3-1과 동일하되, 이제 `Post.password`는 (컨버터가 저장/조회 경계에서 암/복호화를 대신 처리하므로) 서비스·컨트롤러 어디서도 평문 그대로 다루면 됩니다.

---

### 4. MyBatis 프로젝트에서 사용하기 (demoApp `users` 테이블 실제 구현)

demoApp은 MyBatis 3.5.16(`mybatis-spring-boot-starter`)만 사용합니다. 아래는 `users` 테이블의 주민등록번호(`id_no`)/전화번호(`phone`) 컬럼을 KEK-DEK로 암호화하고, Blind Index로 검색하고, Redis로 캐싱하는 실제 프로덕션 코드입니다.

#### 4-1. 도메인별 `EnvelopeCryptoTypeHandler` 서브클래스

`EnvelopeCryptoTypeHandler`는 `EnvelopeCryptoService` 하나에 고정된 컬럼 하나를 담당합니다. MyBatis는 `typeHandler=...`를 **클래스**로만 참조할 수 있어서 도메인/컬럼마다 별도 서브클래스가 필요합니다 — `mybatis-spring-boot-starter`가 Spring 빈으로 등록된 TypeHandler를 인식하므로, 생성자로 원하는 도메인의 `EnvelopeCryptoService`를 주입받게만 만들면 됩니다:

```java
package com.xaan.demo.config.mybatis;

import com.xaan.vault.crypto.envelope.EnvelopeCryptoService;
import com.xaan.vault.crypto.mybatis.EnvelopeCryptoTypeHandler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

// users.id_no/users.phone을 user-pii 도메인 DEK로 암/복호화한다. users 테이블은 KEK-DEK 도입 시점에
// 초기화되어 레거시(비-봉투 포맷) 데이터가 없으므로, 아래 BoardPasswordTypeHandler와 달리 읽기 경로에도
// 안전하게 걸 수 있다.
@Component
public class UserPiiTypeHandler extends EnvelopeCryptoTypeHandler {
    public UserPiiTypeHandler(@Qualifier("userPiiCryptoService") EnvelopeCryptoService userPiiCryptoService) {
        super(userPiiCryptoService);
    }
}
```

같은 앱 안에 있는 `BoardPasswordTypeHandler`는 정반대 제약을 가진 대조 사례입니다 — `board` 테이블에는 이 라이브러리 도입 이전의 레거시 포맷 데이터가 약 4.6만 건 섞여 있어, **쓰기 경로에만** 걸립니다(자세한 이유는 4-4절 참고).

#### 4-2. Mapper에서 컬럼 단위로 지정

```java
package com.xaan.demo.domain.mapper;

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

    // 업무용 조회 - id_no/phone은 UserPiiTypeHandler가 투명하게 복호화해 평문으로 돌려준다.
    @Select("select id, user_id, password, username, id_no, phone, id_no_blind_idx, phone_blind_idx " +
            "from users where user_id = #{userId}")
    @Results({
            @Result(column = "id_no", property = "residentRegistrationNumber", typeHandler = UserPiiTypeHandler.class),
            @Result(column = "phone", property = "phone", typeHandler = UserPiiTypeHandler.class),
            @Result(column = "id_no_blind_idx", property = "residentRegistrationNumberBlindIndex"),
            @Result(column = "phone_blind_idx", property = "phoneBlindIndex")
    })
    Optional<User> findByUserId(String userId);

    // 로그인 검증 전용 - BCrypt 비교에는 password만 있으면 되고 id_no/phone은 필요 없다. 그 컬럼들을 굳이
    // 복호화하면(findByUserId처럼) PII 쪽 ciphertext 문제 하나가 이 계정의 로그인 자체를 막아버리게 된다.
    @Select("select id, user_id, password, username from users where user_id = #{userId}")
    Optional<User> findAuthByUserId(String userId);

    // 목록/검색 조회 - id_no/phone은 일부러 typeHandler 없이 ciphertext 그대로 반환한다. 행이 여러 개인
    // 조회이므로, 한 행의 ciphertext만 문제가 있어도 findByUserId처럼 typeHandler를 걸었다면 전체 조회가
    // 예외로 죽어 나머지 정상 행까지 볼 수 없게 된다. 복호화는 UserService.search()가 행별로 개별 시도한다.
    @Select("""
            <script>
            select id, user_id, password, username, id_no, phone, id_no_blind_idx, phone_blind_idx
            from users
            <where>
                <if test="name != null and name != ''">and username like concat('%', #{name}, '%')</if>
                <if test="phoneBlindIndex != null and phoneBlindIndex != ''">and phone_blind_idx = #{phoneBlindIndex}</if>
                <if test="rrnBlindIndex != null and rrnBlindIndex != ''">and id_no_blind_idx = #{rrnBlindIndex}</if>
            </where>
            order by id desc
            </script>
            """)
    @Results({
            @Result(column = "id_no", property = "residentRegistrationNumber"),
            @Result(column = "phone", property = "phone"),
            @Result(column = "id_no_blind_idx", property = "residentRegistrationNumberBlindIndex"),
            @Result(column = "phone_blind_idx", property = "phoneBlindIndex")
    })
    List<User> search(@Param("name") String name,
                       @Param("phoneBlindIndex") String phoneBlindIndex,
                       @Param("rrnBlindIndex") String rrnBlindIndex);
}
```

이제 `User.residentRegistrationNumber`/`phone`은 `insert()`와 `findByUserId()` 경로에서는 항상 평문입니다 — Service는 저장 전 암호화, 단건 조회 후 복호화를 신경 쓸 필요가 없습니다. 다만 `search()`처럼 여러 행을 한 번에 다루는 목록 조회는 의도적으로 typeHandler를 걸지 않았다는 점이 핵심입니다(4-3절에서 이어짐).

#### 4-3. Service — 저장/단건 조회/목록 조회를 다르게 다루기

```java
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserMapper userMapper;
    private final PasswordService passwordService;
    private final UserSearchCacheService userSearchCacheService;

    @CacheEvict(value = "userSearchRaw", allEntries = true)
    @Transactional
    public Long register(UserRegisterRequestDto dto) {
        // ... 입력 검증 생략 ...

        // 주민등록번호/전화번호는 평문 그대로 넘긴다 - UserMapper.insert()의 UserPiiTypeHandler가
        // AES-GCM으로 암호화해 저장한다.
        User user = User.builder()
                .userId(dto.getUserId())
                .password(passwordService.hashUserPassword(dto.getPassword()))
                .username(dto.getUsername())
                .residentRegistrationNumber(dto.getResidentRegistrationNumber())
                .phone(normalizedPhone)
                .residentRegistrationNumberBlindIndex(passwordService.computeRrnBlindIndex(dto.getResidentRegistrationNumber()))
                .phoneBlindIndex(passwordService.computePhoneBlindIndex(normalizedPhone))
                .build();

        userMapper.insert(user);
        return user.getId();
    }

    // userMapper.search()는 id_no/phone을 ciphertext 그대로 돌려준다(4-2절 참고) - 여기서 행별로
    // 개별 복호화를 시도해, 한 행의 ciphertext에 문제가 있어도 그 행만 표시를 대체하고 나머지 행은
    // 정상적으로 보여준다.
    public List<UserResponseDto> search(String name, String phone, String residentRegistrationNumber) {
        String phoneBlindIndex = (phone == null || phone.isEmpty())
                ? null : passwordService.computePhoneBlindIndex(normalizePhone(phone));
        String rrnBlindIndex = (residentRegistrationNumber == null || residentRegistrationNumber.isEmpty())
                ? null : passwordService.computeRrnBlindIndex(residentRegistrationNumber);
        return userMapper.search(name, phoneBlindIndex, rrnBlindIndex).stream()
                .map(user -> new UserResponseDto(
                        user,
                        passwordService.decryptUserPiiForDisplay(user.getResidentRegistrationNumber()),
                        passwordService.decryptUserPiiForDisplay(user.getPhone())))
                .collect(Collectors.toList());
    }
}
```

`decryptUserPiiForDisplay(...)`는 실패해도 예외를 던지지 않고 대체 문자열을 반환하는, 목록 화면 전용 fail-soft 복호화입니다(`PasswordService`):

```java
public String decryptUserPiiForDisplay(String encryptedText) {
    if (encryptedText == null || encryptedText.isEmpty()) {
        return encryptedText;
    }
    try {
        return userPiiCryptoService.decrypt(encryptedText);
    } catch (RuntimeException e) {
        logger.warn("Failed to decrypt user-pii value for display: {}", e.getMessage());
        return "(복호화 실패)"; // 한 행이 깨져도 나머지 행은 정상 표시
    }
}
```

#### 4-4. 주의: 레거시/비정형 데이터가 섞인 컬럼에는 읽기 경로에 TypeHandler를 걸지 말 것

`users`(4-1의 `UserPiiTypeHandler`)와 `board`(`BoardPasswordTypeHandler`)의 차이가 정확히 이 문제를 보여줍니다. `board` 테이블에는 이 라이브러리 도입 이전의 레거시 포맷 비밀번호가 약 4.6만 건 섞여 있어, `@Results`로 읽기 경로에까지 TypeHandler를 걸면 그 데이터를 스치는 **모든** `SELECT`가 `CryptoException`으로 깨집니다. demoApp의 실제 `BoardMapper`는 그래서 쓰기 경로에만 겁니다:

```java
// password는 쓰기 경로에서만 BoardPasswordTypeHandler를 거친다(암호화) - SELECT는 그대로 암호문을
// 반환한다(복호화하지 않음). 비밀번호 확인은 PasswordService.validateBoardPassword()가
// EnvelopeCryptoService.validate() 안에서 명시적으로 처리한다.
@Insert("insert into board (title, content, author, password, created_date, modified_date) " +
        "values (#{title}, #{content}, #{author}, " +
        "#{password,typeHandler=com.xaan.demo.config.mybatis.BoardPasswordTypeHandler}, now(), now())")
int insert(Board board);

@Select("select id, title, content, author, password, created_date, modified_date from board where id = #{id}")
Board findById(Long id); // password는 typeHandler 없이 암호문 그대로 반환
```

`users`처럼 이 라이브러리 도입 시점에 테이블이 초기화되어 레거시 데이터가 없다는 보장이 있을 때만 읽기·쓰기 양쪽에 걸어도 안전합니다. 그런 보장이 없다면 4-3절의 `search()`/`decryptUserPiiForDisplay()`처럼 raw로 읽고 행별로 안전하게 복호화하는 패턴을 쓰세요.

#### 4-5. Redis 캐싱과 self-invocation 함정

demoApp에는 `/users`(캐시 없음)와 동일한 결과를 Redis로 캐싱하는 `/users2`가 있습니다. 처음 구현했을 때는 `UserService` 안에 `@Cacheable` 메서드를 두고 `search()`에서 `this.searchRawCached(...)`처럼 같은 클래스 안에서 직접 호출했는데, **`@Cacheable`은 Spring이 만든 프록시를 거쳐야만 동작하고, 같은 클래스 안에서의 호출(self-invocation)은 그 프록시를 우회**해서 캐싱이 조용히 아예 동작하지 않았습니다(Redis에 아무것도 쌓이지 않았지만 예외도 없어 알아채기 어려웠습니다). 고친 방법은 캐싱 대상 메서드를 별도 빈으로 분리하는 것입니다:

```java
// UserService에서 분리한 이유: @Cacheable은 Spring 프록시를 거쳐야 동작하는데, 같은 클래스 안에서
// @Cacheable 메서드를 this로 호출(self-invocation)하면 프록시를 우회해 캐싱이 조용히 동작하지 않는다.
// 캐싱 메서드를 별도 빈에 두면 UserService가 실제 Spring 관리 참조를 통해 호출하므로 프록시가 개입한다.
@RequiredArgsConstructor
@Service
public class UserSearchCacheService {
    private final UserMapper userMapper;

    // 캐싱 대상은 반드시 이 raw 조회여야 한다 - userMapper.search()가 id_no/phone을 복호화하지 않고
    // 그대로 반환하므로, Redis에 저장되는 값도 항상 ciphertext뿐이다(평문 PII가 캐시에 올라가지 않는다).
    @Cacheable(value = "userSearchRaw", key = "(#name ?: '') + '|' + (#phoneBlindIndex ?: '') + '|' + (#rrnBlindIndex ?: '')")
    public List<User> search(String name, String phoneBlindIndex, String rrnBlindIndex) {
        return userMapper.search(name, phoneBlindIndex, rrnBlindIndex);
    }
}
```

```java
// UserService.searchCached() - userSearchCacheService(별도 빈)를 거쳐야 @Cacheable이 실제로 적용된다.
public List<UserResponseDto> searchCached(String name, String phone, String residentRegistrationNumber) {
    String phoneBlindIndex = /* ... 4-3과 동일하게 계산 ... */;
    String rrnBlindIndex = /* ... */;
    return userSearchCacheService.search(name, phoneBlindIndex, rrnBlindIndex).stream()
            .map(user -> new UserResponseDto(
                    user,
                    passwordService.decryptUserPiiForDisplay(user.getResidentRegistrationNumber()),
                    passwordService.decryptUserPiiForDisplay(user.getPhone())))
            .collect(Collectors.toList());
}
```

복호화는 캐시 조회 **이후**에 매번 수행되므로, 캐시 적중 여부와 무관하게 Redis에는 평문 PII가 절대 올라가지 않습니다. 또한 `register()`에는 `@CacheEvict(value = "userSearchRaw", allEntries = true)`가 걸려 있습니다 — 신규 가입자가 어떤 검색 조합에든 걸릴 수 있으므로, 그렇지 않으면 캐시 TTL 동안 방금 가입한 사용자가 `/users2`에서 보이지 않게 됩니다.

이 self-invocation 함정 자체는 MyBatis 고유 문제가 아니라 Spring AOP 프록시의 일반적인 제약입니다 — JPA 프로젝트에서 `@Cacheable`/`@Transactional` 등 프록시 기반 애노테이션을 쓸 때도 동일하게 적용됩니다.

---

### 5. 암호화된 컬럼 검색 — Blind Index (demoApp `users` 테이블 실제 구현)

AES-GCM은 매번 랜덤 IV를 쓰므로 같은 평문도 암호문이 매번 달라집니다 - `WHERE phone = ?`처럼 암호문 컬럼을 직접 검색할 방법이 없다는 뜻입니다. Blind Index는 이 문제를 푸는 표준적인 방법으로, 평문에 대해 **키가 고정된 결정적 HMAC**을 계산해 암호화된 컬럼 옆에 별도 컬럼으로 저장해 두고, 검색할 때는 같은 방식으로 검색어의 HMAC을 계산해 그 컬럼을 `=`로 조회합니다. **정확히 일치하는 경우만** 찾을 수 있고(LIKE 부분 검색 불가), 컬럼 하나당 별도의 키를 씁니다(도메인/DEK와는 무관 - DEK 로테이션이 blind index 값에 영향을 주지 않고, 그 반대도 마찬가지). `BlindIndexService` 빈 구성은 2절의 `CryptoConfig`에 이미 포함되어 있습니다 — JPA/MyBatis 어느 쪽이든 그대로 재사용합니다.

Vault에는 KEK/DEK와 마찬가지로 KV-v2 시크릿 하나에 `key` 필드로 저장합니다(버전 관리는 하지 않음 - blind index 키 교체는 전체 재인덱싱이 필요한 별도 작업이라 KEK/DEK식 점진적 로테이션 대상이 아닙니다):

```bash
vault kv put -mount=ebiz_service ebiz_db/blind-index/user-phone \
  key="<Base64URL 인코딩된 32바이트 랜덤 키>"

vault kv put -mount=ebiz_service ebiz_db/blind-index/user-rrn \
  key="<Base64URL 인코딩된 32바이트 랜덤 키>"
```

#### 5-1. 저장 시 — 암호화 값과 blind index를 함께 저장 (`UserService.register`)

```java
User user = User.builder()
        // ... userId/password/username/phone 등 ...
        .residentRegistrationNumberBlindIndex(passwordService.computeRrnBlindIndex(residentRegistrationNumber))
        .phoneBlindIndex(passwordService.computePhoneBlindIndex(normalizedPhone))
        .build();
userMapper.insert(user); // id_no_blind_idx/phone_blind_idx는 평문 컬럼, id_no/phone은 typeHandler가 암호화
```

`PasswordService`는 `BlindIndexService`를 그대로 위임할 뿐입니다:

```java
public String computeRrnBlindIndex(String residentRegistrationNumber) {
    return rrnBlindIndexService.compute(residentRegistrationNumber);
}

public String computePhoneBlindIndex(String phone) {
    return phoneBlindIndexService.compute(phone);
}
```

#### 5-2. 검색 시 — 검색어의 blind index로 조회 (`UserService.search`)

```java
public List<UserResponseDto> search(String name, String phone, String residentRegistrationNumber) {
    String phoneBlindIndex = (phone == null || phone.isEmpty())
            ? null : passwordService.computePhoneBlindIndex(normalizePhone(phone));
    String rrnBlindIndex = (residentRegistrationNumber == null || residentRegistrationNumber.isEmpty())
            ? null : passwordService.computeRrnBlindIndex(residentRegistrationNumber);
    return userMapper.search(name, phoneBlindIndex, rrnBlindIndex) /* ... */;
}

private String normalizePhone(String phone) {
    return phone.replaceAll("[^0-9]", "");
}
```

`normalizePhone(...)`으로 하이픈 등을 제거하는 정규화는 저장 시점(`register`)과 검색 시점(`search`) 모두 **반드시 동일하게** 적용됩니다 — 다르게 정규화하면 같은 번호인데도 blind index가 달라져 조용히 매칭에 실패합니다. `BlindIndexService.compute()` 자체는 정규화를 하지 않으므로, 호출 전 정규화는 항상 호출하는 쪽(`UserService`)의 책임입니다.

#### 5-3. 목록 화면 표시 — 복호화 후 마스킹

검색 결과를 그대로 노출하지 않고, 복호화한 원문을 다시 마스킹해서 보여줍니다(`UserResponseDto` 실제 코드 — 전화번호는 앞 3자리, 주민등록번호는 3~5번째 자리만 남기고 나머지는 `*`):

```java
public UserResponseDto(User entity, String decryptedResidentRegistrationNumber, String decryptedPhone) {
    this.id = entity.getId();
    this.userId = entity.getUserId();
    this.username = entity.getUsername();
    this.residentRegistrationNumber = maskResidentRegistrationNumber(decryptedResidentRegistrationNumber);
    this.phone = maskPhone(decryptedPhone);
}

private static String maskPhone(String phone) {
    if (!isAllDigits(phone) || phone.length() <= 3) {
        return phone; // "(복호화 실패)" 같은 표시 문구는 숫자만이 아니므로 그대로 통과
    }
    return phone.substring(0, 3) + "*".repeat(phone.length() - 3);
}

private static String maskResidentRegistrationNumber(String rrn) {
    if (!isAllDigits(rrn) || rrn.length() < 5) {
        return rrn;
    }
    return "*".repeat(2) + rrn.substring(2, 5) + "*".repeat(rrn.length() - 5);
}
```

즉 하나의 PII 값이 DB에는 암호문(`id_no`/`phone`) + 평문 HMAC(`id_no_blind_idx`/`phone_blind_idx`)로 나뉘어 저장되고, 검색은 HMAC으로, 화면 표시는 "복호화 → 마스킹" 순서로 처리됩니다 — 원문 전체가 화면에 노출되는 지점은 없습니다.

---

### DEK 로테이션

```java
@Service
public class KeyRotationAdminService {

    private final DekRotationSupport rotationSupport;

    public KeyRotationAdminService(KekService kek, DekProvider dekProvider) {
        this.rotationSupport = new DekRotationSupport(kek, dekProvider);
    }

    public int rotateBoardDek() {
        return rotationSupport.rotate("board"); // 새 버전 번호를 반환
    }
}
```

`rotate()`는 새 DEK를 생성해 KEK로 wrap한 뒤 새 버전으로 저장하고 "current"로 지정합니다. 이전 버전은 `DekProvider`에 그대로 남아 있으므로, 다음 앱 재기동 시 `DomainKeyRing`이 신규/기존 버전을 모두 로드해 과거에 암호화된 데이터도 계속 복호화할 수 있습니다.

### DEK 로테이션 이후 — 기존 행 재암호화 배치

`rotate()`는 새 DEK 버전을 만들 뿐, 이미 저장된 행은 여전히 구버전으로 암호화된 채로 남아 있습니다. `currentVersion()`/`versionOf(...)`로 이미 최신인 행을 건너뛰면서 재암호화합니다. **`CryptoException`을 별도로 잡아야 합니다** — 이 라이브러리로 암호화된 적이 전혀 없는 행(예: 이 봉투 포맷 도입 이전의 레거시 데이터)이 섞여 있으면 `versionOf`가 반환하는 값이 우연히 `currentVersion()`과 다를 때 `decrypt()`가 호출되고, 헤더 바이트가 사실상 무작위라 `CryptoException`(도메인 불일치 또는 존재하지 않는 DEK 버전)이 나는데, 이건 실제 실패가 아니라 "이 라이브러리 포맷이 아니니 건드리지 말 것"이라는 신호입니다. demoApp에서 이걸 `failed`로 잘못 집계했다가 운영 DB에서 4만 건 이상의 오탐 에러 로그가 찍힌 뒤 고친 실전 사례가 있습니다 — 처음부터 아래처럼 구분해서 짜는 걸 권장합니다(도메인당 컬럼 하나를 가정한 예시; demoApp의 `DekReencryptionService`/`DekOpsRunner`가 실제 구현):

```java
public MigrationResult reencryptDomain(EnvelopeCryptoService domainService, List<MyRow> rows) {
    int migrated = 0, skipped = 0, notEnvelopeFormat = 0, failed = 0;
    for (MyRow row : rows) {
        String ciphertext = row.getEncryptedColumn();
        if (ciphertext == null || ciphertext.isEmpty()) {
            skipped++;
            continue;
        }
        try {
            if (domainService.versionOf(ciphertext) == domainService.currentVersion()) {
                skipped++;   // 이미 최신 버전 - 복호화/재암호화 안 함
                continue;
            }
            String plain = domainService.decrypt(ciphertext);
            row.setEncryptedColumn(domainService.encrypt(plain));
            migrated++;
        } catch (CryptoException e) {
            notEnvelopeFormat++;   // 이 라이브러리 포맷이 아님 - 행별 로깅 없이 그냥 건너뜀 (많을 수 있음)
        } catch (RuntimeException e) {
            failed++;               // 진짜 예기치 못한 에러만 여기로 - 행별로 로깅해서 조사
        }
    }
    return new MigrationResult(migrated, skipped, notEnvelopeFormat, failed);
}
```

여러 번 실행해도 안전합니다(idempotent) — 이미 최신 버전인 행은 `versionOf(...) == currentVersion()`에서 걸려 건너뜁니다.

### KEK 로테이션

DEK 로테이션과 달리 KEK 로테이션은 **실제 데이터를 전혀 건드리지 않고, 도메인 수만큼의 wrapped DEK만 재wrap**하면 끝납니다. 다만 순서가 중요합니다 — 새 KEK 버전을 발급한 뒤, **옛 버전과 새 버전을 모두 로드한 `KekService`로 재wrap을 마쳐야만** 옛 KEK를 지울 수 있습니다.

```java
@Service
public class KeyRotationAdminService {

    private final KekProvider kekProvider;
    private final DekProvider dekProvider;
    private final KekRotationSupport rotationSupport;

    public KeyRotationAdminService(KekProvider kekProvider, DekProvider dekProvider) {
        this.kekProvider = kekProvider;
        this.dekProvider = dekProvider;
        this.rotationSupport = new KekRotationSupport(kekProvider);
    }

    /** 1단계: 새 KEK 버전 발급 (옛 버전은 그대로 유지). */
    public int issueNewKek() {
        return rotationSupport.issueNewKekVersion();
    }

    /** 2단계: 새 KEK 버전을 반영한 KekService로, 지정한 도메인의 모든 DEK를 재wrap. */
    public void rewrap(String domain) {
        KekService kekRing = KekService.load(kekProvider); // 옛 버전 + 새 버전 모두 로드됨
        rotationSupport.rewrapDomainDeks(kekRing, dekProvider, domain);
    }

    /** 3단계: 모든 도메인의 재wrap이 끝났다고 확인된 뒤에만 호출. */
    public void retireOldKek(int oldVersion) {
        kekProvider.retire(oldVersion);
    }
}
```

전체 운영 절차(발급 → 재wrap → 검증 → 폐기, 재기동 타이밍, 롤백 시나리오 포함)는 demoApp 저장소의 `KEY_ROTATION_RUNBOOK.md`에 절차도와 함께 상세히 정리되어 있습니다.

## API 문서

### KekService

| 생성자/메서드 | 설명 |
|--------|------|
| `static load(KekProvider)` | `KekProvider`에서 모든 KEK 버전과 현재 버전을 읽어 링을 구성 |
| `KekService(Map<Integer,byte[]> kekByVersion, int currentVersion)` | 버전별 KEK를 직접 주입 |
| `KekService(byte[] rawKekBytes)` | 테스트 등 단일 키(버전 1)만 필요한 경우용 |
| `currentVersion()` | 현재 wrap에 사용되는 KEK 버전 번호 |
| `wrap(byte[] plaintextDek)` | 현재 버전 KEK로 DEK를 감싸 저장용 바이트로 변환 (`kekVersion` 헤더 포함) |
| `unwrap(byte[] wrappedDek)` | 헤더의 `kekVersion`에 맞는 KEK로 wrapped DEK를 평문으로 복원 |

### KekProvider / VaultKekProvider / KekRotationSupport

| 타입 | 역할 |
|------|------|
| `KekProvider` | 버전별 KEK 저장소 인터페이스 (`loadAll`, `loadCurrentVersion`, `store`, `retire`) |
| `VaultKekProvider` | Vault KV-v2 기반 구현체 (`kek-v{n}` 필드 + `current-version`) |
| `KekRotationSupport` | `issueNewKekVersion()`로 새 버전 발급, `rewrapDomainDeks(...)`로 도메인의 모든 DEK를 새 버전으로 재wrap |

### DekProvider / VaultDekProvider

`store(...)`에 더해 `retire(String domain, int version)`이 추가되었습니다 — 더 이상 필요 없는(모든 데이터가 새 버전으로 넘어간) DEK 버전을 영구 삭제합니다. **현재 버전은 retire할 수 없습니다.**

### EnvelopeCryptoService

| 메서드 | 파라미터 | 반환 | 설명 |
|--------|----------|------|------|
| `static forDomain(byte domainCode, String domain, KekService, DekProvider)` | - | `EnvelopeCryptoService` | 도메인의 모든 DEK 버전을 unwrap해 메모리 캐시를 구성 |
| `encrypt(String plainText)` | 평문 | Base64 URL-safe 문자열 | 현재 버전 DEK로 AES-256 GCM 암호화 |
| `decrypt(String encryptedText)` | 암호문 | 평문 | 헤더의 버전에 맞는 DEK로 복호화. 도메인/버전 불일치 시 `CryptoException` |
| `validate(String input, String storedEncrypted)` | 평문, 저장된 암호문 | `boolean` | 상수 시간 비교로 Timing Attack 방지, 복호화 실패 시 `false` |
| `currentVersion()` | - | `int` | `encrypt()`가 지금 사용 중인 DEK 버전 — 로테이션 후 재암호화 배치가 "이 값으로 수렴시켜야 할 목표 버전"으로 사용 |
| `versionOf(String encryptedText)` | 암호문 | `int` | 복호화하지 않고 헤더의 `keyVersion`만 읽음 — 재암호화 배치가 `versionOf(row) != currentVersion()`인 행만 골라 처리하도록 해 이미 최신인 행은 건너뜀 |

### 암호화 데이터 형식 (EnvelopeCryptoService, 컬럼에 저장되는 값)

```
Base64URL( domainCode(1B) | keyVersion(1B) | IV(12B) | Ciphertext(N bytes) | GCM Auth Tag(16 bytes) )
```

- **domainCode**: 도메인마다 고유한 1바이트 값 — 다른 도메인 DEK로 복호화를 시도하면 즉시 실패
- **keyVersion**: DEK 버전 — DEK 로테이션 후에도 과거 버전으로 암호화된 데이터를 계속 복호화하기 위한 정보
- **IV**: 12 bytes (96 bits) — 매 암호화 시 `SecureRandom`으로 생성
- **GCM Auth Tag**: 16 bytes (128 bits) — 데이터 무결성 검증

### Wrapped DEK 형식 (KekService, Vault의 `dek-v{n}` 필드에 저장되는 값)

```
kekVersion(1B) | IV(12B) | Ciphertext(32 bytes, DEK 자체) | GCM Auth Tag(16 bytes)
```

- **kekVersion**: 이 DEK를 wrap한 KEK 버전 — KEK 로테이션 후에도 옛 버전 KEK로 wrap된 DEK를 계속 unwrap하기 위한 정보. 별도의 Vault 필드가 아니라 wrapped 바이트 자체에 포함되어 있어(self-describing), `WrappedDek`/`DekProvider`는 이 값을 알 필요가 없음

### BlindIndexService / BlindIndexKeyProvider

| 타입/메서드 | 설명 |
|------|------|
| `BlindIndexService.forIndex(String indexName, BlindIndexKeyProvider)` | 지정한 인덱스 이름의 키를 로드해 서비스를 구성 |
| `BlindIndexService.withKey(byte[])` | 테스트 등 provider 없이 키를 직접 주입 |
| `compute(String plainText)` | HMAC-SHA256으로 결정적 인덱스 값 계산 (Base64 URL-safe). 정규화는 호출 전 애플리케이션 책임 |
| `BlindIndexKeyProvider` | 인덱스 이름별 HMAC 키 저장소 인터페이스 (`loadKey`, `storeKey`) - DEK와 달리 버전 없음 |
| `VaultBlindIndexKeyProvider` | Vault KV-v2 기반 구현체, `{basePath}/{indexName}`의 `key` 필드에 저장 |

### EnvelopeCryptoTypeHandler (MyBatis)

| 항목 | 설명 |
|------|------|
| 패키지 | `com.xaan.vault.crypto.mybatis` |
| 상속 | `org.apache.ibatis.type.BaseTypeHandler<String>` (`mybatis` 의존성은 `compileOnly` - MyBatis 미사용 프로젝트엔 강제되지 않음) |
| 사용법 | 도메인별 `EnvelopeCryptoService`를 주입받는 서브클래스를 만들어 Mapper의 `#{prop,typeHandler=...}`/`@Result(typeHandler=...)`에서 참조 |
| 동작 | `setParameter`에서 `encrypt()`, `getResult`에서 `decrypt()` - `null`/빈 문자열은 그대로 통과 |
| 주의 | 레거시/비정형 데이터가 섞인 컬럼의 읽기 경로에 걸면 그 데이터를 스치는 모든 `SELECT`가 `CryptoException`으로 깨짐 - [4-4. 주의: 레거시/비정형 데이터가 섞인 컬럼에는 읽기 경로에 TypeHandler를 걸지 말 것](#4-4-주의-레거시비정형-데이터가-섞인-컬럼에는-읽기-경로에-typehandler를-걸지-말-것) 참고 |

### 예외 클래스

| 예외 | 부모 클래스 | 발생 시점 |
|------|-------------|-----------|
| `CryptoException` | `RuntimeException` | 암호화/복호화 실패, 도메인/버전 불일치 시 |
| `KeyLoadingException` | `CryptoException` | Vault에서 KEK/DEK 로딩 실패 시 |

## 보안 고려사항

| 항목 | 설명 |
|------|------|
| **키 계층 분리** | KEK는 Vault에만 존재하며 데이터를 직접 암호화하지 않음 — DEK를 wrap하는 용도로만 사용 |
| **도메인 격리** | 서비스 도메인마다 독립된 DEK를 사용해 한 도메인의 키 유출이 다른 도메인 데이터로 번지지 않음 |
| **키 관리** | KEK/wrapped DEK 모두 소스 코드에 하드코딩하지 않고 Vault에서 런타임에 로드 |
| **Vault Token** | 환경변수 `VAULT_TOKEN`으로 관리. 소스/설정 파일에 커밋 금지 |
| **GCM 모드** | 매 암호화 시 랜덤 IV를 생성하므로 동일 평문도 다른 암호문 생성 |
| **인증 암호화** | GCM 모드의 Auth Tag로 데이터 변조 탐지 |
| **Timing Attack 방지** | `validate()` 메서드는 `MessageDigest.isEqual()`로 상수 시간 비교 |
| **DEK 로테이션** | 암호문에 포함된 `keyVersion`으로 DEK 교체 후에도 과거 데이터 복호화 가능 |
| **KEK 로테이션** | wrapped DEK에 포함된 `kekVersion`으로 KEK 교체 후에도 옛 버전으로 wrap된 DEK를 계속 unwrap 가능 — 실제 데이터 재암호화 없이 도메인 수만큼의 DEK만 재wrap하면 됨 |
| **Fail-fast** | `spring.cloud.vault.fail-fast=true` 설정 시 Vault 미연결 시 앱 시작 차단 |

## Troubleshooting

### Vault 연결 실패

```
KeyLoadingException: Failed to load KEK from Vault
```

**확인 사항:**
1. Vault 서버가 실행 중인지 확인: `vault status`
2. `spring.cloud.vault.uri` 설정 확인
3. `VAULT_TOKEN` 환경변수 설정 확인
4. Vault 토큰 만료 여부 확인: `vault token lookup`

### DEK를 찾을 수 없음

```
KeyLoadingException: No DEK versions found for domain '...' at ...
```

**확인 사항:**
1. `vault.dek.base-path` 아래 `{domain}` 시크릿이 실제로 존재하는지: `vault kv get -mount=ebiz_service ebiz_db/dek/board`
2. 시크릿에 `dek-v1`, `current-version` 필드가 모두 있는지
3. `current-version`이 가리키는 버전의 `dek-v{n}` 필드가 실제로 존재하는지

### KEK를 unwrap할 수 없음

```
CryptoException: No KEK version ... loaded
```

**가능한 원인:**
- 그 wrapped DEK를 wrap했던 KEK 버전이 지금 로드된 `KekService`에 없음 — 보통 옛 KEK 버전을 로드하지 않은 상태에서(또는 이미 retire된 뒤) 아직 재wrap되지 않은 DEK를 unwrap하려 할 때 발생
- KEK 로테이션 절차(발급 → 재wrap → 검증 → 폐기) 순서를 지키지 않고 옛 버전을 먼저 지웠을 가능성 — `KEY_ROTATION_RUNBOOK.md` 참고

### 복호화 실패

```
CryptoException: Envelope domain mismatch: expected ... but got ...
```

**가능한 원인:**
- 다른 도메인의 `EnvelopeCryptoService`로 복호화를 시도함
- 암호문이 이 라이브러리의 봉투 포맷이 아님(예: 다른 방식으로 암호화된 값)

## Release History

### v0.0.10 (2026-08-29) — critical fix for v0.0.9

**`EnvelopeCryptoTypeHandler` was silently encrypting every unrelated `String` column in the application, not just the one it was assigned to.** Found in demoApp right after v0.0.9 went live: a user registration threw `value too long for type character varying(50)` on the `user_id` column - the plain `#{userId}` parameter (no `typeHandler=` attribute at all) had been AES-GCM encrypted, turning a 10-character id into a ~54-character ciphertext. The same thing was silently happening to any other untouched `String` column/parameter across the app - e.g. `board.title`/`content`/`author` in demoApp - without necessarily erroring, meaning data could have been getting corrupted (wrongly encrypted) with no visible failure wherever the ciphertext happened to still fit its column.

**Root cause:** `EnvelopeCryptoTypeHandler` extended MyBatis's `BaseTypeHandler<T>`, which itself extends `TypeReference<T>`. Spring Boot's MyBatis auto-configuration registers every `TypeHandler` bean in the application context via `TypeHandlerRegistry.register(TypeHandler<?>)` - and that method, when it can't find an explicit `@MappedTypes` annotation, falls back to auto-discovering the mapped type via `TypeReference.getRawType()` (a MyBatis 3.1.0+ convenience feature). Since `BaseTypeHandler<String>` always resolves that to `String.class`, the handler got registered as *the* default handler for the entire `String` type - not scoped to the one column it was written for. Removing `@MappedTypes` (the fix attempted when this was first written) does nothing to prevent this, since the `TypeReference` auto-discovery path runs independently of that annotation.

**Fix:** `EnvelopeCryptoTypeHandler` now implements the bare `TypeHandler<String>` interface directly instead of extending `BaseTypeHandler<String>` - no `TypeReference`, so the auto-discovery branch never triggers, and `TypeHandlerRegistry.register(...)` falls through to registering the handler only by its own class (reachable solely via explicit `typeHandler=` references, exactly as intended). Method names changed accordingly: `setNonNullParameter(...)` → `setParameter(...)` (now also responsible for the `null` check `BaseTypeHandler` used to do for you), `getNullableResult(...)` → `getResult(...)`.

**Added a regression test** (`registeringTheHandlerDoesNotMakeItTheDefaultHandlerForString`) that registers the handler into a real `TypeHandlerRegistry` the same way Spring Boot's auto-configuration does, and asserts `getTypeHandler(String.class)` still returns MyBatis's built-in handler, not this one - while `getMappingTypeHandler(TestTypeHandler.class)` does return it, confirming explicit-reference lookup still works.

**Migration**: if you're on v0.0.9 and have any subclass calling the old method names, rename `setNonNullParameter` → `setParameter` and `getNullableResult` → `getResult`. No SQL/schema changes needed. **If v0.0.9 was ever deployed with live traffic, audit for silently-encrypted plain `String` columns** - anything that went through a `#{...}` parameter or `@Select` result column with no explicit `typeHandler=`, in any mapper, while a `TypeHandler` bean from this library was registered in the same `SqlSessionFactory`.

### v0.0.9 (2026-08-26)

**Blind Index + MyBatis TypeHandler 지원 추가** — Spring Boot + MyBatis 프로젝트에서 최소한의 코드 변경으로 컬럼 암호화를 적용하고, 암호화된 컬럼을 검색할 수 있도록 하는 두 가지 독립적인 기능.

**Changes:**
- `com.xaan.vault.crypto.mybatis.EnvelopeCryptoTypeHandler` 추가 (`BaseTypeHandler<String>` 상속) - Mapper 컬럼에 붙이면 Service 계층의 명시적 `encrypt()`/`decrypt()` 호출 없이 JDBC 파라미터/`ResultSet` 경계에서 투명하게 암/복호화됨. `mybatis`는 `compileOnly` 의존성으로 추가해 MyBatis를 쓰지 않는 소비 프로젝트에는 강제되지 않음(런타임에는 이미 MyBatis를 쓰는 프로젝트의 클래스패스에 있는 것을 그대로 사용)
- `com.xaan.vault.crypto.blindindex` 패키지 추가: `BlindIndexService`(HMAC-SHA256 기반 결정적 인덱스 계산), `BlindIndexKeyProvider`/`VaultBlindIndexKeyProvider`(필드별 키 저장, Vault KV-v2). AES-GCM 암호문은 검색이 불가능하므로(매번 랜덤 IV), 정확히 일치하는 값을 찾아야 하는 컬럼(전화번호, 주민등록번호 등)에 별도 컬럼으로 나란히 저장해 `WHERE blind_idx = ?`로 조회하는 용도. DEK/KEK와 무관한 별도 키 - 로테이션은 지원하지 않고(전체 재인덱싱이 필요한 별도 작업), 필드마다 키를 분리해 한 필드의 키 교체/유출이 다른 필드에 영향을 주지 않게 함
- `EnvelopeCryptoTypeHandlerTest`는 실제 H2 인메모리 JDBC 커넥션으로 검증(Mock이 아님) - Mapper가 실제로 보게 될 것과 동일하게, 원본 컬럼에는 암호문이 저장되고 핸들러를 통해 읽으면 평문이 복원되는지 확인
- 기능 변경 없음, 순수 추가(non-breaking)

### v0.0.8 (2026-08-21)

**PasswordHasher 추가 (BCrypt 단방향 해시)** — 로그인 비밀번호처럼 원문 복구가 필요 없는 값을 위한 유틸리티. Vault/KEK/DEK와는 무관하지만(BCrypt는 외부 키가 필요 없음), 애플리케이션이 "비밀번호 관련 크립토 로직은 전부 vault-crypto에서" 가져오도록 일원화하기 위해 여기 추가했습니다.

**Changes:**
- `PasswordHasher` 추가 (`com.xaan.vault.crypto`) — `hash(String)`/`matches(String, String)`, 내부적으로 `BCryptPasswordEncoder` 사용
- `spring-security-crypto:6.4.1`을 `implementation` 의존성으로 추가 (라이브러리 소비 프로젝트의 컴파일 클래스패스에는 노출되지 않고, 런타임에는 전이적으로 포함됨)
- 기능 변경 없음, 순수 추가(non-breaking)

### v0.0.7 (2026-08-20)

**재암호화 배치를 위한 버전 조회 API 추가** — DEK 로테이션 런북의 "점진적 재암호화" 단계가 실제로 구현 가능하도록 하는 최소한의 API.

**Changes:**
- `EnvelopeCryptoService.currentVersion()` 추가 — `encrypt()`가 지금 쓰는 DEK 버전 조회
- `EnvelopeCryptoService.versionOf(String)` 추가 — 복호화 없이 암호문 헤더의 `keyVersion`만 읽음. 재암호화 배치가 이미 최신 버전인 행을 건너뛸 수 있게 해줌
- 기능 변경 없음, 순수 추가(non-breaking)

### v0.0.6 (2026-08-20)

**KEK 로테이션 지원 (Breaking change)** — KEK를 버전 관리 없이 단일 값으로만 다루던 갭을 메꿨습니다. 이전 구조에서는 Vault의 `kek` 값을 교체하는 순간 모든 도메인의 모든 DEK unwrap이 동시에 실패했습니다(전체 장애).

**Changes:**
- `KekService`를 `DomainKeyRing`과 동일한 패턴으로 재작성 — 여러 KEK 버전을 메모리에 보관하고, wrapped DEK 앞에 붙은 `kekVersion(1B)` 헤더로 올바른 버전을 선택해 unwrap
- `KekProvider`/`VaultKekProvider` 추가 — KEK도 DEK처럼 `kek-v{n}` + `current-version` 형식으로 Vault에 버전별 저장
- `KekRotationSupport` 추가 — `issueNewKekVersion()`(신규 KEK 버전 발급)과 `rewrapDomainDeks(...)`(도메인의 모든 DEK를 새 KEK 버전으로 재wrap, 실제 데이터는 건드리지 않음)
- `DekProvider`/`VaultDekProvider`와 `KekProvider`/`VaultKekProvider` 모두에 `retire(...)` 추가 — 더 이상 필요 없는 버전을 영구 삭제(현재 버전은 거부)
- `KekService`의 기존 `VaultOperations` 직접 생성자 제거 — `KekService.load(KekProvider)`로 대체 (Breaking)

**Breaking**: wrapped DEK 바이트 포맷이 바뀌었습니다(`kekVersion` 헤더 1바이트 추가). v0.0.5 이하에서 만든 wrapped DEK는 새 코드로 unwrap할 수 없으므로, KEK/DEK를 다시 생성해야 합니다.

**Migration**: `new KekService(vaultOperations, kekPath)`를 쓰던 코드는 `VaultKekProvider` + `KekService.load(...)` 조합으로 옮기세요. Vault의 `kek` 필드는 `kek-v1` + `current-version=1`로 다시 저장해야 합니다.

### v0.0.5 (2026-08-19)

**버전 정렬** — 기능 변경 없음. demoApp이 `0.0.4 → 0.0.5`로 버전을 올리는 데 맞춰, vault-crypto도 `0.0.3 → 0.0.5`로 올려 두 프로젝트의 버전 번호를 통일했다(`0.0.4`는 건너뜀).

### v0.0.3 (2026-08-19)

**Breaking change** — `VaultCryptoService`(단일 키 방식)를 완전히 제거했습니다. 이 클래스를 사용하던 기존 소비 프로젝트는 더 이상 지원하지 않기로 결정했습니다.

**Changes:**
- `VaultCryptoService.java` 삭제 (v0.0.2에서 `@Deprecated`로 표시했던 클래스)
- README를 KEK-DEK 봉투 암호화(`EnvelopeCryptoService`) 중심으로 재작성

**Migration**: v0.0.2 이하에서 `VaultCryptoService`를 쓰던 코드는 [사용 가이드](#사용-가이드)를 참고해 `KekService` + `DekProvider` + `EnvelopeCryptoService.forDomain(...)` 조합으로 옮겨야 합니다. 기존 단일 키로 암호화된 데이터는 새 봉투 포맷과 호환되지 않으므로 별도 재암호화가 필요합니다.

### v0.0.2 (2026-08-19)

**KEK-DEK 봉투 암호화 추가** — `com.xaan.vault.crypto.envelope` 패키지 신설.

**Features:**
- `KekService`: Vault에서 KEK를 로드하고 DEK를 wrap/unwrap
- `WrappedDek`, `DekProvider`/`VaultDekProvider`: 도메인별 wrapped DEK를 Vault KV-v2에 버전별로 저장/조회
- `DomainKeyRing`: 도메인별 unwrap된 DEK를 메모리에 캐시 (버전별)
- `EnvelopeCryptoService`: 도메인 스코프 encrypt/decrypt/validate, `domainCode`+`keyVersion` 헤더로 도메인 격리와 키 로테이션 지원
- `DekRotationSupport`: DEK 로테이션(신규 버전 발급) 유틸

### v0.0.1 patch (2026-05-18)

**Code Quality Improvements** — 소스 코드 품질 개선 및 예외 처리 통일.

**Changes:**
- 중복 import 제거 (`StandardCharsets` 2중 import)
- `encrypt()`, `decrypt()` 예외 타입을 `RuntimeException` → `CryptoException`으로 통일
- `decrypt()` 입력 검증 강화: 최소 길이 체크를 IV(12 bytes) → IV + TAG(28 bytes)로 변경
- `decrypt()` 에서 `CryptoException` re-throw 처리 추가

### v0.0.1 (2026-05-08)

**Initial release** — Standalone Vault-based encryption library for Spring Boot applications (단일 키 방식, v0.0.3에서 제거됨).

## 라이선스

Internal use only.
