# Práctica 1 – Autenticación y cifrado TLS/SSL en el API Backend

API REST con **Java 17 + Spring Boot 3.5 + Spring Security** que:

- Sirve **solo por HTTPS** (TLS 1.2 / 1.3) con un keystore PKCS12.
- Redirige (302) a HTTPS cualquier petición HTTP en texto plano.
- Protege las rutas del API con **JWT (Bearer token)**, devolviendo `401` / `403` con JSON personalizado.
- Habilita **CORS** para un frontend Angular (`http(s)://localhost:4200`).
- Registra los eventos de seguridad en la categoría de log `SECURITY_AUDIT`.

## Requisitos

- JDK 17 o superior
- Maven 3.9+ (o el Maven integrado de tu IDE)

## Ejecutar

```bash
mvn spring-boot:run
```

| Puerto | Protocolo | Función |
|--------|-----------|---------|
| `8443` | HTTPS     | API (TLS 1.2 / 1.3) |
| `8080` | HTTP      | Solo redirige a `https://localhost:8443` |

Pruebas automáticas (incluye handshake TLS real, versiones de protocolo y redirección):

```bash
mvn test
```

## Keystore / certificado

El repositorio incluye un keystore **solo de desarrollo** (`src/main/resources/keystore/devkeystore.p12`, contraseña `changeit`, alias `securebackend`, SAN `localhost`/`127.0.0.1`) y su certificado público en `certs/localhost.crt`.

Para regenerarlos:

```bash
./scripts/generate-keystore.sh
```

Comando equivalente (`keytool`):

```bash
keytool -genkeypair -alias securebackend -keyalg RSA -keysize 2048 -storetype PKCS12 \
  -keystore src/main/resources/keystore/devkeystore.p12 -storepass changeit -keypass changeit \
  -validity 825 -dname "CN=localhost, OU=Dev, O=SecureBackend, L=Chihuahua, ST=Chihuahua, C=MX" \
  -ext "SAN=dns:localhost,ip:127.0.0.1,ip:0:0:0:0:0:0:0:1"
```

Configuración en `application.yml`:

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore/devkeystore.p12
    key-store-type: PKCS12
    key-store-password: changeit
    key-alias: securebackend
    enabled-protocols: TLSv1.2,TLSv1.3
```

> En producción **no** uses este keystore: define `SSL_KEYSTORE_PATH`, `SSL_KEYSTORE_PASSWORD`, `SSL_KEY_ALIAS` y `JWT_SECRET` por variables de entorno.

## Usuarios de demostración

| Usuario | Contraseña  | Roles |
|---------|-------------|-------|
| `admin` | `Admin123!` | `ROLE_ADMIN`, `ROLE_USER` |
| `user`  | `User123!`  | `ROLE_USER` |

## Endpoints

| Método | Ruta | Acceso |
|--------|------|--------|
| `POST` | `/api/auth/login` | Público – devuelve el JWT |
| `GET`  | `/api/public/health` | Público (el campo `secure` indica si llegó por TLS) |
| `GET`  | `/api/users/me` | Autenticado |
| `GET`  | `/api/admin/dashboard` | Solo `ROLE_ADMIN` |

## Verificación con curl

```bash
# 1) Handshake TLS con el certificado de desarrollo
curl -v --cacert certs/localhost.crt https://localhost:8443/api/public/health

# 2) Forzar versiones de TLS
curl --cacert certs/localhost.crt --tlsv1.2 --tls-max 1.2 https://localhost:8443/api/public/health   # OK
curl --cacert certs/localhost.crt --tlsv1.3 --tls-max 1.3 https://localhost:8443/api/public/health   # OK
curl --cacert certs/localhost.crt --tlsv1.1 --tls-max 1.1 https://localhost:8443/api/public/health   # FALLA (rechazado)

# 3) Inspeccionar el handshake con openssl
openssl s_client -connect localhost:8443 -tls1_3 -CAfile certs/localhost.crt </dev/null

# 4) HTTP en texto plano => redirección 302 a HTTPS
curl -i http://localhost:8080/api/public/health

# 5) Sin token => 401
curl -i --cacert certs/localhost.crt https://localhost:8443/api/users/me

# 6) Login y uso del token
TOKEN=$(curl -s --cacert certs/localhost.crt -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"User123!"}' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')

curl -i --cacert certs/localhost.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/users/me          # 200
curl -i --cacert certs/localhost.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/admin/dashboard   # 403 (rol insuficiente)

# 7) Credenciales incorrectas => 401 con mensaje personalizado
curl -i --cacert certs/localhost.crt -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" -d '{"username":"user","password":"mala"}'
```

### Postman

1. *Settings → Certificates → CA Certificates*: carga `certs/localhost.crt` (o desactiva temporalmente *SSL certificate verification* solo en desarrollo).
2. `POST https://localhost:8443/api/auth/login` con el JSON de login y copia `accessToken`.
3. En las demás peticiones: *Authorization → Bearer Token* y pega el token.

## Formato de errores

Todos los errores tienen la misma forma:

```json
{
  "timestamp": "2026-10-20T19:10:00Z",
  "status": 401,
  "error": "Unauthorized",
  "code": "TOKEN_EXPIRED",
  "message": "El token de autenticación ha expirado. Inicie sesión nuevamente.",
  "path": "/api/users/me"
}
```

| Código | HTTP | Cuándo |
|--------|------|--------|
| `AUTH_REQUIRED` | 401 | Petición sin token |
| `TOKEN_INVALID` | 401 | Token mal formado, firma inválida o emisor incorrecto |
| `TOKEN_EXPIRED` | 401 | Token vencido |
| `BAD_CREDENTIALS` | 401 | Usuario o contraseña incorrectos en el login |
| `ACCESS_DENIED` | 403 | Autenticado pero sin el rol requerido |
| `VALIDATION_ERROR` / `MALFORMED_REQUEST` | 400 | Cuerpo inválido |

### Errores de handshake TLS

El handshake ocurre **antes** de que exista una petición HTTP, por lo que el servidor no puede responder con un JSON: el cliente recibe una alerta TLS (p. ej. `handshake_failure` / `protocol_version`) y curl/Postman muestran el error. Del lado del servidor se pueden diagnosticar así:

- Subir a `DEBUG` el logger `org.apache.tomcat.util.net.NioEndpoint` (hay una línea comentada en `application.yml`).
- Arrancar con `-Djavax.net.debug=ssl:handshake` para ver el detalle completo.
- Una petición HTTP en texto plano al puerto 8443 recibe de Tomcat un `400` indicando que esa combinación host/puerto requiere TLS; en el puerto 8080 recibe la redirección a HTTPS.

Los eventos de autenticación/autorización (`LOGIN_OK`, `LOGIN_FALLIDO`, `TOKEN_RECHAZADO`, `ACCESO_NO_AUTENTICADO`, `ACCESO_DENEGADO`) se escriben con el logger `SECURITY_AUDIT`, sin contraseñas ni tokens.

## Estructura

```
src/main/java/com/example/securebackend
├── SecureBackendApplication.java
├── config
│   ├── SecurityConfig.java        # SecurityFilterChain, CORS, reglas por URL, HSTS
│   ├── HttpsRedirectConfig.java   # conector HTTP :8080 -> redirección a HTTPS
│   ├── UserConfig.java            # usuarios demo (BCrypt) y AuthenticationManager
│   └── JwtProperties.java
├── security
│   ├── JwtService.java            # emisión y validación de JWT (HMAC)
│   ├── JwtAuthenticationFilter.java
│   ├── RestAuthenticationEntryPoint.java   # 401
│   ├── RestAccessDeniedHandler.java        # 403
│   ├── ErrorResponseWriter.java
│   └── SecurityAuditLogger.java
└── web
    ├── AuthController.java        # POST /api/auth/login
    ├── ApiController.java
    ├── GlobalExceptionHandler.java
    └── dto/ (LoginRequest, LoginResponse, ErrorResponse)
```

## Conectar con Angular

Desde el frontend (origen `http://localhost:4200` o `https://localhost:4200`) basta con llamar a `https://localhost:8443/api/...` y enviar `Authorization: Bearer <token>` (por ejemplo con un `HttpInterceptor`). Los orígenes permitidos se cambian con `CORS_ALLOWED_ORIGINS`.
Si el navegador rechaza el certificado autofirmado, abre una vez `https://localhost:8443/api/public/health` y acepta la excepción, o instala `certs/localhost.crt` como certificado de confianza.

## Mapa de criterios de aceptación

| Criterio | Dónde |
|----------|-------|
| Keystore PKCS12 generado | `src/main/resources/keystore/`, `scripts/generate-keystore.sh` |
| Solo TLS 1.2 / 1.3 sobre HTTPS | `application.yml` (`server.ssl.*`), `TlsIntegrationTest` |
| HTTP redirigido / rechazado | `HttpsRedirectConfig` (`app.http-redirect.enabled=false` para rechazar), `TlsIntegrationTest` |
| `SecurityFilterChain` protege el API | `SecurityConfig` |
| Token Bearer/JWT obligatorio | `JwtAuthenticationFilter`, `JwtService` |
| `401` / `403` | `RestAuthenticationEntryPoint`, `RestAccessDeniedHandler`, `SecurityIntegrationTest` |
| Errores y eventos personalizados | `ErrorResponse`, `GlobalExceptionHandler`, `SecurityAuditLogger` |
| CORS para Angular | `SecurityConfig#corsConfigurationSource` |
