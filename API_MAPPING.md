# Mapeamento de APIs: Pax/Neptune → Tectoy SDK

## Resumo de Mudanças

| Funcionalidade | Pax/Neptune | Tectoy | Status |
|---|---|---|---|
| **Obter Instância de Segurança** | `IPed` via `NeptuneLiteUser.getDal()` | `PosSecurityManager.getDefault()` | ✓ Substituir |
| **Escrever Chave AES** | `IPed.writeAesKey()` | `PosSecurityManager.PedWriteKey()` | ✓ Substituir |
| **Escrever Chave TR31** | `IPed.writeTR31Key()` | `PosSecurityManager.PedWriteKey()` | ✓ Substituir |
| **Obter KCV** | `IPed.getKCV()` | Não encontrado direto (usar storage) | ⚠️ Alternativa |
| **Tipos de Chaves** | `EPedKeyType` enum | Constantes `PED_TLK`, `PED_TMK`, etc. | ✓ Substituir |
| **Modo de Check** | `EAesCheckMode` enum | Valores inteiros (0, 0x80) | ✓ Substituir |

---

## 1. OBTER INSTÂNCIA DE SEGURANÇA

### Pax/Neptune
```java
import com.pax.neptunelite.api.NeptuneLiteUser;
import com.pax.dal.IPed;

IPed ped = NeptuneLiteUser.getInstance()
    .getDal(context)
    .getPed(EPedType.INTERNAL);
```

### Tectoy ✓
```java
import com.pos.tectoy.sdk.PosSecurityManager;

PosSecurityManager securityManager = PosSecurityManager.getDefault();
```

---

## 2. TIPOS DE CHAVES

### Pax/Neptune
```java
EPedKeyType.AES_TMK.getPedkeyType()  // Usa enum
EPedKeyType.AES_TMK                   // Direto do enum
```

### Tectoy ✓
```java
PosSecurityManager.PED_TMK    // Constante int
PosSecurityManager.PED_TLK    // Transport Layer Key
PosSecurityManager.PED_BDK    // Base Derivation Key
PosSecurityManager.PED_TPK    // Terminal PIN Key
// ... muitos outros
```

---

## 3. ESCREVER CHAVE AES

### Pax/Neptune
```java
ped.writeAesKey(
    EPedKeyType.AES_TMK.getPedkeyType(),    // srcKeyType
    (byte) 0,                                 // srcKeyIdx
    EPedKeyType.AES_TMK.getPedkeyType(),    // dstKeyType
    (byte) 99,                                // dstKeyIdx
    keyBytes,                                 // key data
    EAesCheckMode.KCV_NONE,                  // check mode
    null                                      // check buffer
);
```

### Tectoy ✓
```java
PedKeyInfo pedKeyInfo = new PedKeyInfo();
pedKeyInfo.srcKeyType = PosSecurityManager.PED_TLK;
pedKeyInfo.srcKeyIdx = 0;
pedKeyInfo.dstKeyType = PosSecurityManager.PED_TMK;
pedKeyInfo.dstKeyIdx = 1;
pedKeyInfo.dstKeyLen = 32;
pedKeyInfo.dstKeyData = keyBytes;
pedKeyInfo.dstAlgorithm = 0x10;  // AES

PedKcvInfo pedKcvInfo = new PedKcvInfo();
pedKcvInfo.checkMode = 0;  // KCV_NONE
pedKcvInfo.checkBuf = new byte[0];

int result = securityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);
```

---

## 4. ESCREVER CHAVE TR31

### Pax/Neptune
```java
byte[] tr31Bytes = tr31Block.getBytes(StandardCharsets.US_ASCII);

ped.writeTR31Key(
    EPedKeyType.AES_TMK.getPedkeyType(),
    (byte) 99,
    (byte) index,
    tr31Bytes
);
```

### Tectoy ✓
```java
byte[] tr31Bytes = HexUtil.hexToBytes(tr31BlockHex);

PedKeyInfo pedKeyInfo = new PedKeyInfo();
pedKeyInfo.srcKeyType = PosSecurityManager.PED_TLK;
pedKeyInfo.srcKeyIdx = 0;
pedKeyInfo.dstKeyType = PosSecurityManager.PED_TMK;
pedKeyInfo.dstKeyIdx = index;
pedKeyInfo.dstKeyData = tr31Bytes;
pedKeyInfo.dstAlgorithm = 0x10;

PedKcvInfo pedKcvInfo = new PedKcvInfo();
pedKcvInfo.checkMode = 0;
pedKcvInfo.checkBuf = new byte[0];

int result = securityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);
```

---

## 5. OBTER KCV

### Pax/Neptune
```java
byte[] buffer = new byte[16];
byte[] kcvBytes = ped.getKCV(
    EPedKeyType.AES_TMK,
    (byte) index,
    (byte) 3,
    buffer
);
String kcv = HexUtil.bytesToHex(kcvBytes).substring(0, 6);
```

### Tectoy ⚠️
```java
// Tectoy não tem método direto getKCV()
// Alternativa 1: Verificar resposta da API RKL (usa KCV da resposta)
// Alternativa 2: Implementar cálculo de KCV localmente
// Alternativa 3: Usar persistência local de KCVs

// IMPLEMENTAÇÃO RECOMENDADA - usar KCV da resposta da API
String kcv = apiResponse.optString("kcv", "");
```

---

## 6. MAPEAMENTO DE MODOS DE CHECK

| Modo | Pax | Tectoy |
|------|-----|--------|
| Sem verificação | `EAesCheckMode.KCV_NONE` | `0` |
| Com verificação | `EAesCheckMode.KCV_CHECK` | `0x80` |

---

## 7. ALGORITMOS SUPORTADOS

| Algoritmo | Tectoy |
|-----------|--------|
| DES | `0x00` |
| AES | `0x10` |
| SM4 | `0x20` |

---

## 8. CÓDIGOS DE RETORNO

### Pax/Neptune
```java
try {
    ped.writeTR31Key(...);
    // sucesso
} catch (PedDevException e) {
    // erro
}
```

### Tectoy ✓
```java
int result = securityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);

if (result == 0) {
    Logger.success("Operação bem-sucedida");
} else {
    String errorMsg = EPedReturnsSP.getReturnSP(result);
    Logger.error("Falha: " + errorMsg);
}
```

---

## 9. OBTER SERIAL NUMBER (SN)

### Pax/Neptune
```java
import com.pax.neptunelite.api.NeptuneLiteUser;
import com.pax.dal.entity.ETermInfoKey;

String sn = NeptuneLiteUser.getInstance()
    .getDal(context)
    .getSys()
    .getTermInfo()
    .get(ETermInfoKey.SN);
```

### Tectoy ✓
```java
import com.pos.tectoy.sdk.PosSystemManager;

PosSystemManager sysManager = PosSystemManager.getDefault();
String sn = sysManager.getDeviceInfo().getSerialNumber();
// Ou alternativa:
String sn = sysManager.getSN();  // depende da versão
```

---

## 10. ESTRUTURAS DE DADOS

### PedKeyInfo (Tectoy)
```java
public class PedKeyInfo {
    public int srcKeyType;      // Tipo da chave fonte
    public int srcKeyIdx;       // Índice da chave fonte
    public int dstKeyType;      // Tipo da chave destino
    public int dstKeyIdx;       // Índice da chave destino
    public int dstKeyLen;       // Comprimento da chave
    public byte[] dstKeyData;   // Dados da chave
    public int dstAlgorithm;    // Algoritmo (0x10 = AES, 0x00 = DES)
}
```

### PedKcvInfo (Tectoy)
```java
public class PedKcvInfo {
    public int checkMode;       // Modo de verificação (0 = none, 0x80 = check)
    public byte[] checkBuf;     // Buffer de verificação
}
```

---

## CHECKLIST DE ADAPTAÇÃO

- [ ] Substituir `NeptuneLiteUser` por `PosSystemManager` (para SN)
- [ ] Substituir `IPed` por `PosSecurityManager`
- [ ] Converter `EPedKeyType` enums para constantes `PED_*`
- [ ] Converter `EAesCheckMode` enums para valores inteiros
- [ ] Adaptar `writeAesKey()` para `PedWriteKey()`
- [ ] Adaptar `writeTR31Key()` para `PedWriteKey()`
- [ ] Adaptar tratamento de `getKCV()` (usar valores da API)
- [ ] Adaptar tratamento de exceções para códigos de retorno inteiros
- [ ] Testar compatibilidade com SDK Tectoy v1.13.202605121416

---

## NOTAS IMPORTANTES

1. **PedWriteKey() é universal**: Tanto `writeAesKey()` quanto `writeTR31Key()` usam o mesmo método em Tectoy
2. **KCV via API**: Como Tectoy não tem `getKCV()` nativo, use o KCV retornado pela API RKL
3. **Sem Exceções**: Tectoy usa códigos de retorno inteiros, não exceções
4. **Acesso Singleton**: `PosSecurityManager.getDefault()` retorna a instância singleton
5. **Compatibilidade**: Todos os métodos Tectoy são bloqueantes (synchronous)
