# vault-crypto

Vault 기반 암호화 라이브러리 for Spring Boot applications.

## 개요

HashiCorp Vault에서 암호화 키를 읽어와 AES-256 GCM 모드로 암호화/복호화를 수행합니다.

## 기능

- Vault kv-v2 백엔드 지원
- AES-256 암호화/복호화 (GCM 모드, 인증 암호화)
- Spring Cloud Vault 통합
- Base64 인코딩/디코딩

## 빌드

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

./gradlew clean build publishToMavenLocal
```

빌드된 JAR는 `~/.m2/repository/com/xaan/vault-crypto/0.0.1/`에 설치됩니다.

## 의존성 추가

### Maven
```xml
<dependency>
    <groupId>com.xaan</groupId>
    <artifactId>vault-crypto</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Gradle
```groovy
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation 'com.xaan:vault-crypto:0.0.1'
}
```

## 사용법

### 1. Vault 설정 (application.properties)
```properties
spring.cloud.vault.uri=http://192.168.2.57:8200
spring.cloud.vault.token=${VAULT_TOKEN}
spring.cloud.vault.fail-fast=false
```

### 2. Vault Secret 설정
```bash
vault secrets enable -path=ebiz_service kv-v2

vault kv put -mount=ebiz_service ebiz_db/data-enc-key \
  fernet-key="NgqOBievnB9500cQOnSQ-cmbBx38KnOiKx5ooQ_e97Y=" \
  description="encryption key for db column"
```

### 3. Java 코드에서 사용
```java
import com.xaan.vault.crypto.VaultCryptoService;
import org.springframework.stereotype.Service;

@Service
public class MyService {
    
    private final VaultCryptoService cryptoService;
    
    public MyService(VaultCryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }
    
    public void example() {
        // 암호화
        String encrypted = cryptoService.encrypt("myPassword");
        System.out.println("Encrypted: " + encrypted);
        
        // 복호화
        String decrypted = cryptoService.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
        
        // 검증
        boolean valid = cryptoService.validate("myPassword", encrypted);
        System.out.println("Valid: " + valid);
    }
}
```

### 4. 커스텀 Vault 경로 사용
```java
public MyService(VaultOperations vaultOperations) {
    // 기본 경로: "ebiz_service/data/ebiz_db/data-enc-key"
    VaultCryptoService cryptoService = new VaultCryptoService(vaultOperations);
    
    // 또는 커스텀 경로 지정
    VaultCryptoService customService = new VaultCryptoService(
        vaultOperations, 
        "my_mount/data/my_path/my-key"
    );
}
```

## API 문서

### VaultCryptoService

| 메서드 | 설명 |
|--------|------|
| `encrypt(String plainText)` | 평문을 AES-256으로 암호화하고 Base64 인코딩 |
| `decrypt(String encryptedText)` | Base64 디코딩 후 AES-256으로 복호화 |
| `validate(String input, String storedEncrypted)` | 입력값과 저장된 암호화값 비교 |

## 요구사항

- Java 17 이상
- Spring Cloud Vault
- HashiCorp Vault (kv-v2 백엔드)
- 환경 변수 `VAULT_TOKEN` 설정 필요

## 프로젝트 구조

```
vault-crypto/
├── src/main/java/com/xaan/vault/crypto/
│   └── VaultCryptoService.java
├── build.gradle
└── settings.gradle
```

## Release History

### v0.0.1 (2026-05-08)

**Initial release** - Standalone Vault-based encryption library for Spring Boot applications.

**Features:**
- Vault kv-v2 backend support (mount: `ebiz_service`, path: `data/ebiz_db/data-enc-key`)
- AES-256 encryption/decryption (GCM mode, authenticated encryption)
- Spring Cloud Vault integration (`VaultOperations`)
- Base64 encoding/decoding for encrypted values
- `encrypt(plainText)`, `decrypt(encryptedText)`, `validate(input, storedEncrypted)` methods
- Configurable Vault secret path (custom mount/path support)

**Security:**
- Encryption key loaded from HashiCorp Vault at startup
- Fail-fast disabled to allow graceful degradation when Vault is unavailable
- Constant-time validation method to prevent timing attacks

**Dependency:**
```groovy
implementation 'com.xaan:vault-crypto:0.0.1'
```
