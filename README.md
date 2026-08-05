# vault-crypto

HashiCorp Vault 기반 AES-256 GCM 암호화 라이브러리 for Spring Boot

## 개요

`vault-crypto`는 HashiCorp Vault에서 암호화 키를 안전하게 로드하여 AES-256 GCM 모드로 데이터의 암호화/복호화를 수행하는 Spring Boot 라이브러리입니다.

### 주요 특징

- **Vault 통합**: HashiCorp Vault kv-v2 백엔드에서 암호화 키를 안전하게 로드
- **AES-256 GCM**: 인증된 암호화(Authenticated Encryption) 지원
- **Spring 통합**: `VaultOperations`를 통한 Spring Cloud Vault 연동
- **Base64 URL-safe 인코딩**: 암호화된 데이터를 안전하게 문자열로 저장
- **커스텀 예외**: `CryptoException`, `KeyLoadingException`으로 세밀한 오류 처리
- **Timing Attack 방지**: `MessageDigest.isEqual()` 기반 상수 시간 비교

### 아키텍처

```
┌──────────────────────────────────────────────────────────────┐
│                      Your Application                        │
│  (BoardService, UserService, etc.)                           │
├──────────────────────────────────────────────────────────────┤
│                    VaultCryptoService                         │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐   │
│  │ encrypt()  │  │ decrypt()  │  │ validate()           │   │
│  │ AES-256    │  │ AES-256    │  │ constant-time compare│   │
│  │ GCM mode   │  │ GCM mode   │  │                      │   │
│  └────────────┘  └────────────┘  └──────────────────────┘   │
├──────────────────────────────────────────────────────────────┤
│                   Spring Cloud Vault                         │
│              (VaultOperations / VaultTemplate)                │
├──────────────────────────────────────────────────────────────┤
│                  HashiCorp Vault Server                       │
│               kv-v2: fernet-key (32 bytes)                   │
└──────────────────────────────────────────────────────────────┘
```

## 프로젝트 구조

```
vault-crypto/
├── src/main/java/com/xaan/vault/crypto/
│   ├── VaultCryptoService.java    # 핵심 암호화/복호화 서비스
│   ├── CryptoException.java       # 암호화 관련 기본 예외
│   └── KeyLoadingException.java   # Vault 키 로딩 예외
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

빌드된 JAR는 `~/.m2/repository/com/xaan/vault-crypto/0.0.1/`에 설치됩니다.

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
    implementation 'com.xaan:vault-crypto:0.0.1'

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
    <version>0.0.1</version>
</dependency>
```

## Vault 설정

### Step 1: Vault kv-v2 백엔드 활성화

```bash
# kv-v2 백엔드를 원하는 마운트 경로에 활성화
vault secrets enable -path=ebiz_service kv-v2
```

### Step 2: 암호화 키 저장

```bash
# Fernet 키 (32 bytes, Base64URL 인코딩) 저장
vault kv put -mount=ebiz_service ebiz_db/data-enc-key \
  fernet-key="NgqOBievnB9500cQOnSQ-cmbBx38KnOiKx5ooQ_e97Y=" \
  description="encryption key for db column"
```

### Step 3: 키 저장 확인

```bash
vault kv get -mount=ebiz_service ebiz_db/data-enc-key
```

### Step 4: Spring Boot application.properties

```properties
# Vault 서버 연결 설정
spring.cloud.vault.uri=${VAULT_URI:http://192.168.2.57:8200}
spring.cloud.vault.token=${VAULT_TOKEN:hvs.YOUR_TOKEN_HERE}
spring.cloud.vault.fail-fast=true

# Vault KV v2 설정
spring.cloud.vault.kv.enabled=true
spring.cloud.vault.kv.backend=ebiz_service
spring.cloud.vault.kv.application-name=ebiz_db/data-enc-key
spring.cloud.vault.kv.version=2

# vault-crypto에서 사용하는 시크릿 경로 (커스텀 설정)
vault.secret.path=${VAULT_SECRET_PATH:ebiz_service/data/ebiz_db/data-enc-key}
```

> **참고**: `vault.secret.path`의 경로 형식은 `{mount}/data/{secret-path}`입니다.
> kv-v2에서 `data`는 Vault API가 자동으로 삽입하는 경로 세그먼트입니다.

## 사용 가이드

### 기본 사용법

```java
import com.xaan.vault.crypto.VaultCryptoService;
import org.springframework.vault.core.VaultOperations;
import org.springframework.stereotype.Service;

@Service
public class MyService {

    private final VaultCryptoService cryptoService;

    public MyService(VaultOperations vaultOperations) {
        // 기본 경로 사용: "ebiz_service/data/ebiz_db/data-enc-key"
        this.cryptoService = new VaultCryptoService(vaultOperations);
    }

    public void example() {
        // 암호화
        String encrypted = cryptoService.encrypt("민감한 데이터");

        // 복호화
        String decrypted = cryptoService.decrypt(encrypted);

        // 검증 (constant-time comparison)
        boolean isValid = cryptoService.validate("민감한 데이터", encrypted);
    }
}
```

### 커스텀 Vault 경로 사용

```java
@Service
public class MyService {

    private final VaultCryptoService cryptoService;

    public MyService(
            VaultOperations vaultOperations,
            @Value("${vault.secret.path:ebiz_service/data/ebiz_db/data-enc-key}") String vaultPath) {
        // application.properties에서 경로를 읽어 주입
        this.cryptoService = new VaultCryptoService(vaultOperations, vaultPath);
    }
}
```

---

### 실전 예제 1: 게시판 비밀번호 암호화 (양방향)

게시글에 비밀번호를 설정하여, 수정/삭제 시 복호화하여 검증하는 패턴입니다.

#### PasswordService.java — 암호화 서비스 래퍼

```java
@Service
public class PasswordService {

    private final VaultCryptoService vaultCryptoService;

    public PasswordService(
            VaultOperations vaultOperations,
            @Value("${vault.secret.path:ebiz_service/data/ebiz_db/data-enc-key}") String vaultSecretPath) {
        this.vaultCryptoService = new VaultCryptoService(vaultOperations, vaultSecretPath);
    }

    /** 게시글 비밀번호 암호화 (AES-GCM) */
    public String encryptBoardPassword(String password) {
        return vaultCryptoService.encrypt(password);
    }

    /** 게시글 비밀번호 복호화 */
    public String decryptBoardPassword(String encryptedPassword) {
        return vaultCryptoService.decrypt(encryptedPassword);
    }

    /** 게시글 비밀번호 검증 (constant-time) */
    public boolean validateBoardPassword(String rawPassword, String encryptedPassword) {
        return vaultCryptoService.validate(rawPassword, encryptedPassword);
    }
}
```

#### BoardService.java — 게시글 저장/수정 시 암호화 적용

```java
@RequiredArgsConstructor
@Service
public class BoardService {
    private final BoardRepository boardRepository;
    private final PasswordService passwordService;

    // 게시글 저장 — 비밀번호를 암호화하여 DB에 저장
    @Transactional
    public Long save(BoardSaveRequestDto requestDto) {
        Board board = requestDto.toEntity();
        if (board.getPassword() != null && !board.getPassword().isEmpty()) {
            board.updatePassword(
                passwordService.encryptBoardPassword(board.getPassword())
            );
        }
        return boardRepository.save(board).getId();
    }

    // 게시글 수정 — 수정 시에도 비밀번호 재암호화
    @Transactional
    public Long update(Long id, BoardUpdateRequestDto requestDto) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("no article for id=" + id));
        board.update(requestDto.getTitle(), requestDto.getContent());
        if (requestDto.getPassword() != null && !requestDto.getPassword().isEmpty()) {
            board.updatePassword(
                passwordService.encryptBoardPassword(requestDto.getPassword())
            );
        }
        return id;
    }

    // 게시글 비밀번호 검증
    public boolean verifyPassword(Long id, String password) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("no article for id=" + id));
        return passwordService.validateBoardPassword(password, board.getPassword());
    }
}
```

#### REST API 호출 예시

```bash
# 비밀번호가 포함된 게시글 생성
curl -X POST http://localhost:8080/api/v1/posts \
  -H "Content-Type: application/json" \
  -d '{"title":"보안 게시글","content":"비밀 내용입니다","password":"mySecret123"}'
# Returns: 2017588

# DB 확인 — 비밀번호가 Base64 암호화 문자열로 저장됨
# SELECT password FROM ebiz.board WHERE id = 2017588;
# → JrwIlNN9YVMIxpqWvYhlNGfd7CUf1wjOgXAHLRIf0io=
```

---

### 실전 예제 2: 개인정보(주민등록번호) 암호화

양방향 암호화가 필요한 개인정보 필드에 적용하는 패턴입니다.

#### UserService.java — 회원가입 시 개인정보 암호화

```java
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordService passwordService;

    @Transactional
    public Long register(UserRegisterRequestDto dto) {
        // 입력값 검증 (생략)

        // 사용자 로그인 비밀번호 → BCrypt 단방향 해시 (별도 처리)
        String hashedPassword = passwordService.hashUserPassword(dto.getPassword());

        // 주민등록번호 → AES-GCM 양방향 암호화 (vault-crypto 사용)
        String encryptedRRN = passwordService.encryptBoardPassword(
            dto.getResidentRegistrationNumber()
        );

        User user = User.builder()
                .userId(dto.getUserId())
                .password(hashedPassword)               // BCrypt 해시
                .username(dto.getUsername())
                .residentRegistrationNumber(encryptedRRN) // AES-GCM 암호화
                .build();

        return userRepository.save(user).getId();
    }
}
```

> **설계 포인트**: 사용자 로그인 비밀번호는 BCrypt(단방향)를 사용하고,
> 주민등록번호처럼 복호화가 필요한 데이터는 vault-crypto(AES-GCM, 양방향)를 사용합니다.

---

### 실전 예제 3: Python에서 동일 키로 복호화 (검증용)

Java와 동일한 방식으로 Python에서 암호화된 데이터를 복호화할 수 있습니다.

```python
import hvac
import base64
from Crypto.Cipher import AES

# 1. Vault에서 키 로드
client = hvac.Client(url='http://192.168.2.57:8200', token='hvs.YOUR_TOKEN')
secret = client.secrets.kv.v2.read_secret_version(
    path='ebiz_db/data-enc-key', mount_point='ebiz_service'
)
fernet_key = base64.urlsafe_b64decode(secret['data']['data']['fernet-key'])

# 2. 복호화 (Java VaultCryptoService와 동일한 형식)
def decrypt(encrypted_base64, key):
    combined = base64.urlsafe_b64decode(encrypted_base64)
    iv = combined[:12]          # 12 bytes IV
    ciphertext_with_tag = combined[12:]
    tag = ciphertext_with_tag[-16:]       # 마지막 16 bytes = GCM auth tag
    ciphertext = ciphertext_with_tag[:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# 3. 사용
decrypted = decrypt("JrwIlNN9YVMIxpqWvYhl...", fernet_key)
print(f"Decrypted: {decrypted}")
```

**Python 의존성:**
```bash
pip install pycryptodome hvac
```

---

## API 문서

### VaultCryptoService

#### 생성자

| 생성자 | 설명 |
|--------|------|
| `VaultCryptoService(VaultOperations)` | 기본 Vault 경로 사용 (`ebiz_service/data/ebiz_db/data-enc-key`) |
| `VaultCryptoService(VaultOperations, String)` | 커스텀 Vault 경로 지정 |

생성자 호출 시점에 Vault에서 키를 로드합니다. 키 로드 실패 시 `KeyLoadingException`이 발생합니다.

#### 메서드

| 메서드 | 파라미터 | 반환 | 예외 | 설명 |
|--------|----------|------|------|------|
| `encrypt(String plainText)` | 암호화할 평문 | Base64 URL-safe 문자열 | `CryptoException` | AES-256 GCM 암호화. 매 호출 시 랜덤 IV 생성 |
| `decrypt(String encryptedText)` | Base64 URL-safe 암호화 문자열 | 복호화된 평문 | `CryptoException` | AES-256 GCM 복호화 |
| `validate(String input, String storedEncrypted)` | 평문, 저장된 암호화값 | `boolean` | 없음 (내부 처리) | 상수 시간 비교로 Timing Attack 방지 |

#### 암호화 데이터 형식

```
Base64URL( IV(12 bytes) + Ciphertext(N bytes) + GCM Auth Tag(16 bytes) )
```

- **IV**: 12 bytes (96 bits) — 매 암호화 시 `SecureRandom`으로 생성
- **Ciphertext**: 평문 길이와 동일
- **GCM Auth Tag**: 16 bytes (128 bits) — 데이터 무결성 검증

### 예외 클래스

| 예외 | 부모 클래스 | 발생 시점 |
|------|-------------|-----------|
| `CryptoException` | `RuntimeException` | 암호화/복호화 실패 시 |
| `KeyLoadingException` | `CryptoException` | Vault 키 로딩 실패 시 |

#### 예외 처리 예시

```java
try {
    String encrypted = cryptoService.encrypt(sensitiveData);
} catch (KeyLoadingException e) {
    // Vault 연결 실패 또는 키를 찾을 수 없음
    log.error("Vault 키 로딩 실패: {}", e.getMessage());
} catch (CryptoException e) {
    // 암호화 처리 중 오류
    log.error("암호화 실패: {}", e.getMessage());
}
```

## 보안 고려사항

| 항목 | 설명 |
|------|------|
| **키 관리** | 암호화 키는 소스 코드에 하드코딩하지 않고 Vault에서 런타임에 로드 |
| **Vault Token** | 환경변수 `VAULT_TOKEN`으로 관리. 소스/설정 파일에 커밋 금지 |
| **GCM 모드** | 매 암호화 시 랜덤 IV를 생성하므로 동일 평문도 다른 암호문 생성 |
| **인증 암호화** | GCM 모드의 Auth Tag로 데이터 변조 탐지 |
| **Timing Attack 방지** | `validate()` 메서드는 `MessageDigest.isEqual()`로 상수 시간 비교 |
| **Base64URL** | Fernet 키는 URL-safe Base64 인코딩 (`-`, `_` 사용) |
| **Fail-fast** | `spring.cloud.vault.fail-fast=true` 설정 시 Vault 미연결 시 앱 시작 차단 |

## Troubleshooting

### Vault 연결 실패

```
KeyLoadingException: Failed to load encryption key from Vault
```

**확인 사항:**
1. Vault 서버가 실행 중인지 확인: `vault status`
2. `spring.cloud.vault.uri` 설정 확인
3. `VAULT_TOKEN` 환경변수 설정 확인
4. Vault 토큰 만료 여부 확인: `vault token lookup`

### 키를 찾을 수 없음

```
KeyLoadingException: No 'data' field in Vault response
```

**확인 사항:**
1. kv-v2 마운트가 활성화되어 있는지 확인: `vault secrets list`
2. 시크릿 경로가 올바른지 확인: `vault kv get -mount=ebiz_service ebiz_db/data-enc-key`
3. `vault.secret.path`에 `/data/` 세그먼트가 포함되어 있는지 확인 (kv-v2 필수)

### 복호화 실패

```
CryptoException: Error decrypting data
```

**가능한 원인:**
- 암호화 시 사용한 키와 복호화 시 사용하는 키가 다름
- 암호화된 데이터가 손상됨 (DB 저장/조회 과정에서 인코딩 변환)
- Base64 URL-safe와 표준 Base64 혼용

### `@Service` 자동 등록 관련

`vault-crypto`의 `VaultCryptoService`에는 `@Service`가 붙어 있지만, 생성자에 `VaultOperations` 인자가 필요합니다. 소비 프로젝트에서 `VaultOperations` Bean이 등록되어 있으면 Spring이 자동 주입합니다. 커스텀 경로가 필요한 경우에는 직접 Bean을 정의하세요:

```java
@Configuration
public class CryptoConfig {
    @Bean
    public VaultCryptoService vaultCryptoService(
            VaultOperations vaultOperations,
            @Value("${vault.secret.path}") String path) {
        return new VaultCryptoService(vaultOperations, path);
    }
}
```

## Release History

### v0.0.1 patch (2026-05-18)

**Code Quality Improvements** — 소스 코드 품질 개선 및 예외 처리 통일.

**Changes:**
- 중복 import 제거 (`StandardCharsets` 2중 import)
- `encrypt()`, `decrypt()` 예외 타입을 `RuntimeException` → `CryptoException`으로 통일
- `decrypt()` 입력 검증 강화: 최소 길이 체크를 IV(12 bytes) → IV + TAG(28 bytes)로 변경
- `decrypt()` 에서 `CryptoException` re-throw 처리 추가

**Compatibility:** 바이너리 형식 변경 없음. 기존 암호화 데이터와 100% 호환.

**Verified:** demoApp에서 vault-crypto 라이브러리 재통합 후 프로덕션 배포 및 테스트 완료.

### v0.0.1 (2026-05-08)

**Initial release** — Standalone Vault-based encryption library for Spring Boot applications.

**Features:**
- Vault kv-v2 backend support (mount: `ebiz_service`, path: `data/ebiz_db/data-enc-key`)
- AES-256 encryption/decryption (GCM mode, authenticated encryption)
- Spring Cloud Vault integration (`VaultOperations`)
- Base64 URL-safe encoding/decoding for encrypted values
- `encrypt()`, `decrypt()`, `validate()` methods
- Configurable Vault secret path (custom mount/path support)
- Custom exception hierarchy: `CryptoException`, `KeyLoadingException`

**Security:**
- Encryption key loaded from HashiCorp Vault at startup
- Random IV per encryption for semantic security
- Constant-time validation to prevent timing attacks

**Dependency:**
```groovy
implementation 'com.xaan:vault-crypto:0.0.1'
```

## 라이선스

Internal use only.
