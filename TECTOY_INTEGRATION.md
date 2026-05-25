# Integração Tectoy SDK - RKI APP TENG

## Visão Geral

Este documento descreve a integração da SDK Tectoy (`com.pos.tectoy.sdk_V1.13.202605121416.jar`) no projeto RKI APP TENG. A solução foi adaptada do projeto RKI APP que utiliza a SDK Neptune, mas adequada para a API Tectoy.

## Principais Diferenças

### RKI APP (Neptune)
- **SDK**: `NeptuneLiteApi_V4.25.00_20260306.jar`
- **Interface**: `IPed` do Neptune
- **Métodos**: `writeTR31Key()`, `writeAesKey()`, `getKCV()`

### RKI APP TENG (Tectoy)
- **SDK**: `com.pos.tectoy.sdk_V1.13.202605121416.jar`
- **Interface**: `PosSecurityManager`
- **Métodos**: `PedWriteKey()`, `PedKeyInfo`, `PedKcvInfo`

## Arquitetura de Solução

### Classes Criadas

#### 1. **TectoySecurityManager**
`br.zire.rkiapp.crypto.TectoySecurityManager`

Gerenciador de segurança que encapsula todas as operações criptográficas com a SDK Tectoy.

**Métodos principais:**
- `writeKey()` - Escreve chaves genéricas no dispositivo
- `writeTr31Key()` - Escreve chaves em formato TR31
- `getKcv()` - Obtém o KCV (Key Check Value) de uma chave

**Uso:**
```java
TectoySecurityManager securityManager = new TectoySecurityManager(context);
boolean result = securityManager.writeKey(
    PosSecurityManager.PED_TLK,  // srcKeyType
    0,                            // srcKeyIdx
    PosSecurityManager.PED_TMK,  // dstKeyType
    1,                            // dstKeyIdx
    0x10,                         // dstAlgorithm
    0,                            // checkMode
    32,                           // len
    "53F83A5E23BD1EED400B741E67CB5E8CC96F4E58722AD06DDB1ACD5A2575F5DB", // keyHex
    "354176"                      // kcvHex
);
```

#### 2. **TectoyKeyInjectionManager**
`br.zire.rkiapp.crypto.TectoyKeyInjectionManager`

Gerenciador de injeção de chaves adaptado para Tectoy.

**Métodos principais:**
- `injectTr31()` - Injeta chaves em formato TR31
- `injectKbpk()` - Injeta a chave KBPK (Key Block Protection Key)

**Uso:**
```java
TectoyKeyInjectionManager injectionManager = new TectoyKeyInjectionManager(context);
RklProfileKey profileKey = new RklProfileKey();
profileKey.label = "KBPK";
profileKey.slotTargetPhy = 2;
profileKey.kcv = "ABC123";

boolean injected = injectionManager.injectTr31(profileKey, tr31BlockHex);
```

#### 3. **TectoyRklLoadKbpkManager**
`br.zire.rkiapp.rkl.TectoyRklLoadKbpkManager`

Carrega e injeta a chave KBPK usando a SDK Tectoy.

**Fluxo:**
1. Requisita KBPK da API
2. Criptografa com chave pública efêmera
3. Gera assinatura RSA
4. Injeta via `TectoyKeyInjectionManager`

#### 4. **TectoyRklLoadMkManager**
`br.zire.rkiapp.rkl.TectoyRklLoadMkManager`

Carrega e injeta chaves Master Key (MK) usando a SDK Tectoy.

#### 5. **TectoyRklLoadBdkManager**
`br.zire.rkiapp.rkl.TectoyRklLoadBdkManager`

Carrega e injeta chaves Base Derivation Key (BDK) usando a SDK Tectoy.

#### 6. **TectoyRklFlowManager**
`br.zire.rkiapp.rkl.TectoyRklFlowManager`

Orquestrador do fluxo completo de provisioning usando os managers Tectoy.

**Fluxo de execução:**
1. Testa conectividade com servidores
2. Realiza autenticação
3. Carrega detalhes do número de série
4. Carrega cadeia de certificados
5. Gera KeyPair RSA
6. Carrega certificado efêmero
7. Gera CSR (Certificate Signing Request)
8. Solicita emissão de certificado
9. **Carrega KBPK (Tectoy)**
10. **Carrega MK (Tectoy)**
11. **Carrega BDK (Tectoy)**
12. Valida chave pública

## Exemplos de Valores Tectoy

### Exemplo 1: Injetar TLK (Transport Layer Key)
```java
String TLK = "53F83A5E23BD1EED400B741E67CB5E8CC96F4E58722AD06DDB1ACD5A2575F5DB";
String TLKcheckBuf = "354176";

securityManager.writeKey(
    PosSecurityManager.PED_TLK,    // Source Key Type
    0,                              // Source Key Index
    PosSecurityManager.PED_TLK,    // Destination Key Type
    1,                              // Destination Key Index
    0x10,                           // Algorithm (AES)
    0,                              // Check Mode
    32,                             // Key Length
    TLK,                            // Key Data
    TLKcheckBuf                     // Check Value
);
```

### Exemplo 2: Injetar TMK (Transaction Master Key)
```java
String TMK = "117A073FC45E6B27480F3D682B714882E3678B2556F855B0B6F402AAA285DEFE";
String TMKcheckBuf = "D0144K1AD01N00008C30A72FCFC23B8BA23286A5A0150D74E49352B3AF7D18D4A008BF08A0D85537009601AEEBACDC62EA6B9FBAAC18A6C8074C47654094E126910D9506B182A4BD";

securityManager.writeKey(
    PosSecurityManager.PED_TLK,    // Source Key Type
    1,                              // Source Key Index
    PosSecurityManager.PED_TMK,    // Destination Key Type
    1,                              // Destination Key Index
    0x10,                           // Algorithm
    0x80,                           // Check Mode
    32,                             // Key Length
    TMK,                            // Key Data
    TMKcheckBuf                     // Check Value
);
```

## Como Usar No Projeto

### Opção 1: Usar TectoyRklFlowManager
Substituir o uso de `RklFlowManager` por `TectoyRklFlowManager` no `MainActivity`:

```java
// Antes
flowManager = new RklFlowManager(httpClient);

// Depois
flowManager = new TectoyRklFlowManager(httpClient);
```

### Opção 2: Usar Classes Individuais
Para integração customizada, use as classes diretamente:

```java
// Carregador KBPK
TectoyRklLoadKbpkManager kbpkManager = new TectoyRklLoadKbpkManager(httpClient);
boolean kbpkOk = kbpkManager.loadKbpk();

// Carregador MK
TectoyRklLoadMkManager mkManager = new TectoyRklLoadMkManager(httpClient);
boolean mkOk = mkManager.loadMk(profileKey);

// Carregador BDK
TectoyRklLoadBdkManager bdkManager = new TectoyRklLoadBdkManager(httpClient);
boolean bdkOk = bdkManager.loadBdk(profileKey);
```

## Mapeamento de Chaves

| Tipo | Tectoy Constant | Value | Função |
|------|-----------------|-------|--------|
| TLK | `PED_TLK` | - | Transport Layer Key |
| TMK | `PED_TMK` | - | Transaction Master Key |
| BDK | `PED_BDK` | - | Base Derivation Key |
| KBPKChain | `PED_KBPKChain` | - | KBPK Chain |

## Modo de Check

| Modo | Valor | Descrição |
|------|-------|-----------|
| KCV_NONE | 0 | Sem verificação de KCV |
| KCV_DEFAULT | 0x80 | Verificação padrão de KCV |

## Algoritmos Suportados

| Algoritmo | Valor | Descrição |
|-----------|-------|-----------|
| DES | 0x00 | Triple DES |
| AES | 0x10 | Advanced Encryption Standard |

## Tratamento de Erros

Todos os métodos retornam `EPedReturnsSP` que pode ser convertido em texto legível:

```java
int result = posSecurityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);
String errorMessage = EPedReturnsSP.getReturnSP(result);

if (result == 0) {
    Logger.success("Operação bem-sucedida");
} else {
    Logger.error("Falha: " + errorMessage);
}
```

## Logging

Todos os managers utilizam a classe `Logger` para registrar operações:

- `Logger.section()` - Marca início de uma seção
- `Logger.info()` - Log informativo
- `Logger.success()` - Log de sucesso
- `Logger.error()` - Log de erro
- `Logger.warning()` - Log de aviso

## Notas Importantes

1. **Chaves Hexadecimais**: Todas as chaves devem estar em formato hexadecimal (base16)
2. **Check Values**: Os valores de check devem estar codificados corretamente conforme a SDK
3. **Contexto**: Sempre passar o contexto Android para os managers
4. **Permissões**: Certifique-se que o aplicativo tem permissões para acessar o PED
5. **SDK Tectoy**: A SDK Tectoy deve estar incluída no projeto como JAR em `app/libs/`

## Próximos Passos

1. Testar a integração em um dispositivo Tectoy real
2. Validar os valores de chaves e check values
3. Implementar tratamento de exceções específicas da Tectoy
4. Adicionar suporte para diferentes versões de firmware do PED
5. Otimizar o performance da injeção de chaves

## Referências

- Documentação da SDK Tectoy v1.13.202605121416
- Especificação de segurança Tectoy
- Padrão TR-31 para encapsulamento de chaves
