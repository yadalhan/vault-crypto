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
├── build.gradle                   # Gradle 빌드 설정
├── settings.gradle                # 프로젝트 설정
└── README.md
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

빌드된 JAR는 `~/.m2/repository/com/xaan/vault-crypto/0.0.7/`에 설치됩니다.

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
    implementation 'com.xaan:vault-crypto:0.0.7'

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
    <version>0.0.7</version>
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

### 기본 사용법 — 도메인별 EnvelopeCryptoService 구성

```java
import com.xaan.vault.crypto.envelope.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.core.VaultOperations;

@Configuration
public class CryptoConfig {

    @Bean
    public KekProvider kekProvider(
            VaultOperations vaultOperations,
            @Value("${vault.kek.path}") String kekPath) {
        return new VaultKekProvider(vaultOperations, kekPath);
    }

    @Bean
    public KekService kekService(KekProvider kekProvider) {
        return KekService.load(kekProvider); // loads every KEK version once at startup
    }

    @Bean
    public DekProvider dekProvider(
            VaultOperations vaultOperations,
            @Value("${vault.dek.base-path}") String dekBasePath) {
        return new VaultDekProvider(vaultOperations, dekBasePath);
    }

    // 서비스 도메인마다 빈을 하나씩 둔다. domainCode는 도메인마다 고유한 1바이트 값.
    @Bean
    public EnvelopeCryptoService boardCryptoService(KekService kek, DekProvider dekProvider) {
        return EnvelopeCryptoService.forDomain((byte) 1, "board", kek, dekProvider);
    }

    @Bean
    public EnvelopeCryptoService userPiiCryptoService(KekService kek, DekProvider dekProvider) {
        return EnvelopeCryptoService.forDomain((byte) 2, "user-pii", kek, dekProvider);
    }
}
```

`EnvelopeCryptoService.forDomain(...)`이 호출되는 시점(보통 빈 생성 시, 즉 앱 기동 시)에 KEK로 해당 도메인의 DEK를 1회 unwrap해서 메모리에 캐시합니다. 이후 `encrypt()`/`decrypt()`/`validate()` 호출은 Vault를 다시 호출하지 않습니다.

```java
@Service
public class BoardService {

    private final EnvelopeCryptoService boardCryptoService;

    public BoardService(@Qualifier("boardCryptoService") EnvelopeCryptoService boardCryptoService) {
        this.boardCryptoService = boardCryptoService;
    }

    public String example(String password) {
        String encrypted = boardCryptoService.encrypt(password);
        String decrypted = boardCryptoService.decrypt(encrypted);
        boolean matches = boardCryptoService.validate(password, encrypted);
        return encrypted;
    }
}
```

---

### 실전 예제: 게시판 비밀번호 + 개인정보를 별도 도메인으로 분리

```java
@Service
public class PasswordService {

    private final EnvelopeCryptoService boardCryptoService;
    private final EnvelopeCryptoService userPiiCryptoService;

    public PasswordService(
            @Qualifier("boardCryptoService") EnvelopeCryptoService boardCryptoService,
            @Qualifier("userPiiCryptoService") EnvelopeCryptoService userPiiCryptoService) {
        this.boardCryptoService = boardCryptoService;
        this.userPiiCryptoService = userPiiCryptoService;
    }

    // 게시글 비밀번호 (board 도메인 DEK)
    public String encryptBoardPassword(String password) {
        return boardCryptoService.encrypt(password);
    }

    public boolean validateBoardPassword(String rawPassword, String encryptedPassword) {
        return boardCryptoService.validate(rawPassword, encryptedPassword);
    }

    // 주민등록번호 등 개인정보 (user-pii 도메인 DEK — board와 별도 키)
    public String encryptUserPii(String plainText) {
        return userPiiCryptoService.encrypt(plainText);
    }

    public String decryptUserPii(String encryptedText) {
        return userPiiCryptoService.decrypt(encryptedText);
    }
}
```

`board` DEK로 암호화한 값은 `user-pii` 서비스로 복호화를 시도하면 `domainCode` 불일치로 항상 `CryptoException`이 발생합니다 — 도메인 간 키가 섞이지 않는다는 것을 애플리케이션 레벨에서도 보장합니다.

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
