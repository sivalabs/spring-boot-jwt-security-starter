# spring-boot-jwt-security-starter

This is a SpringBoot starter to provide JWT token based security auto-configuration.

## How to use?

### Add the dependency

**Maven** 

```
<dependency>
    <groupId>com.github.sivalabs</groupId>
    <artifactId>spring-boot-jwt-security-starter</artifactId>
    <version>0.0.1</version>
</dependency>
```

**Gradle**

`compile group: 'com.github.sivalabs', name: 'spring-boot-jwt-security-starter', version: '0.0.1'`

With the starter dependency is added, you need to configure a bean of type `org.springframework.security.core.userdetails.UserDetailsService`.

### Configuration

The following configuration properties are available to customize the default behaviour.

| Property | Required | Default Value |
| --- | --- | --- |
| `security.jwt.issuer` | yes | `""` |
| `security.jwt.header` | yes | `Authorization` |
| `security.jwt.expires-in` | yes | `604800` |
| `security.jwt.secret` | yes | `""` |
| `security.jwt.base-path` | yes | `/api/**` |
| `security.jwt.permit-all-paths` | no | `/api/auth/login,/api/auth/refresh` |
| `security.jwt.auth-api-enabled` | no | `true` |
| `security.jwt.create-auth-token-path` | no | `/api/auth/login` |
| `security.jwt.refresh-auth-token-path` | no | `/api/auth/refresh` |
| `security.jwt.auth-me-path` | no | `/api/auth/me` |


If security.jwt.auth-api-enabled property is set to true then following REST endpoints will be available:

### 1. Login/Create Auth Token

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"username":"xyz","password":"xyz"}' \
  http://localhost:8080/api/auth/login
```

**Response JSON:**
```
{
    "access_token": "....",
    "expires_in": "..."
}
```

### 2. Refresh Auth Token

```
curl --header "Authorization: Bearer access_token" \
  --request POST \
  http://localhost:8080/api/auth/refresh
```

**Response JSON:**
```
{
    "access_token": "....",
    "expires_in": "..."
}
```

### 3. Get Authenticated User Info
```
curl --header "Content-Type: application/json" \
  --request GET \
  http://localhost:8080/api/auth/me
```

**Response JSON:**
```
{
    "username": "admin",
    "roles": ["ROLE_USER","ROLE_ADMIN"]
}
```

## Developer Notes

Procedure for deploying to Maven Central https://central.sonatype.org/pages/apache-maven.html

Set version to SNAPSHOT (ex: 1.0.0-SNAPSHOT)

Deploy SNAPSHOT version to https://oss.sonatype.org/content/repositories/snapshots/

`spring-boot-jwt-security-starter> ./mvnw clean deploy -Prelease`

Deploy release version to Maven Central

```
spring-boot-jwt-security-starter> ./mvnw release:clean release:prepare -Prelease
spring-boot-jwt-security-starter> ./mvnw release:perform -Prelease
```
