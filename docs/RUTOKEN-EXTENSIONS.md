# Расширенные функции Рутокена (`C_EX_*`)

Справочник по вендорскому расширению PKCS #11 от Aktiv Co. Нужен затем, что
часть ПО опознаёт библиотеку как рутокеновскую по наличию
`C_EX_GetFunctionListExtended`, и затем, что остальные функции мы собираемся
дореализовывать по мере надобности.

## Источник

Rutoken SDK **v.2026** (релиз 15.05.2026), `rutoken-sdk-latest.zip`
с <https://download.rutoken.ru/Rutoken/SDK/>, каталог `sdk/pkcs11/include/`:

| файл | SHA-256 |
| --- | --- |
| `rtpkcs11.h` | `51f27a6dfbe8a1a1f658f55ddb7d315193daa58170e606a139264dcba04183fb` |
| `rtpkcs11f.h` | `e9014f78682f68685148689a0d99f1dc11a8cf23b65fcbf19a9c04edf055d368` |
| `rtpkcs11t.h` | `69e7924219c370aa8c785617583b29153f06369637d4a9424c657be153979fdd` |

Заголовки Aktiv в репозиторий не копируются. Двоичный интерфейс — раскладка
структур, порядок полей таблицы, значения констант — объявлен своими словами в
`src/lib/pkcs11/rutoken.h`. Приложения по-прежнему подключают заголовки Aktiv;
от нас требуется только совпадать с ними поле в поле.

## Как устроено расширение

Библиотека экспортирует вторую таблицу функций. Точка входа —
`C_EX_GetFunctionListExtended`, устроенная как `C_GetFunctionList`: отдаёт
указатель на статическую `CK_FUNCTION_LIST_EXTENDED`, работает до
`C_Initialize`. Структура начинается с `CK_VERSION version`, дальше идут
34 указателя в фиксированном порядке — **порядок часть ABI**, поля можно
только дописывать в конец.

## Что реализовано у нас

| функция | у нас |
| --- | --- |
| `C_EX_GetFunctionListExtended` | работает всегда, как `C_GetFunctionList` |
| `C_EX_GetTokenInfoExtended` | работает при включённом `FAKE_RUTOKEN_ECP` |
| остальные 32 | `CKR_FUNCTION_NOT_SUPPORTED` |

`C_EX_GetTokenInfoExtended` вне профиля отвечает `CKR_FUNCTION_NOT_SUPPORTED`:
без профиля модуль не Рутокен и не должен отвечать на вопрос, заданный только
Рутокену. Сама таблица отдаётся всегда — скрыть экспорт всё равно нельзя, а
проверять флаг профиля до `C_Initialize` невозможно: он читается из
конфигурации именно там.

Таблица заполнена целиком: `NULL` в любом поле роняет вызывающего, который
берёт указатель по смещению и не проверяет его.

## `CK_TOKEN_INFO_EXTENDED`

Что мы кладём в поля и откуда берём.

| поле | источник |
| --- | --- |
| `ulSizeofThisStructure` | `[in]` размер от вызывающего, `[out]` заполненный; несовпадение → `CKR_BUFFER_TOO_SMALL` |
| `ulTokenType` | `TOKEN_TYPE_RUTOKEN_ECP`; поле объявлено вендором устаревшим, но его ещё читают |
| `ulTokenClass` | `TOKEN_CLASS_ECP` |
| `serialNumber[8]` | тот же серийник, что и в `C_GetTokenInfo`, в BCD — два представления обязаны сходиться |
| `flags` | постоянные возможности эталона + `*_PIN_NOT_DEFAULT` по состоянию токена |
| `ulAdminRetryCountLeft`, `ulUserRetryCountLeft` | выводятся из стандартных флагов: `LOCKED` → 0, `FINAL_TRY` → 1, `COUNT_LOW` → 2, иначе максимум |
| остальное | константы эталонного устройства, собраны в одном именованном блоке в `SoftHSM.cpp` |

### Показания эталонного устройства (14.08.2026)

Сняты `tests/portable/rutoken-reference-dump.c` с `rtPKCS11ECP.dll` владельца.
Всё, что из программного токена не выводится, взято отсюда.

| поле | значение |
| --- | --- |
| `ulSizeofThisStructure` | 164 на Windows (`CK_ULONG` там 4 байта, упаковка 1), 256 на Linux |
| `ulTokenType` / `ulTokenClass` | `0x01` / `0x01` — ECP |
| `ulProtocolNumber` | `0x01` |
| `ulMicrocodeNumber` | `0x1E` (30 — совпадает со старшей версией прошивки) |
| `ulOrderNumber` | `2` |
| `flags` | `0x00001C0F`: `ADMIN_CHANGE_USER_PIN`, `USER_CHANGE_USER_PIN`, `ADMIN_PIN_NOT_DEFAULT`, `USER_PIN_NOT_DEFAULT`, `SUPPORT_JOURNAL`, `USER_PIN_UTF8`, `ADMIN_PIN_UTF8` |
| PIN-коды | оба 6..249, попыток 10 из 10 |
| `serialNumber` | `00 00 00 00 47 73 84 61` при печатном `47738461` — **BCD**, выровнено вправо |
| память | 103200 свободно из 131072 |
| `ATR` | 15 байт `3B8B015275746F6B656E20445320C1`, внутри читается `Rutoken DS` |
| `ulBodyColor` | `0` (`UNKNOWN`) |
| `ulFirmwareChecksum` | `0x4D27D7A2`, флаг `FW_CHECKSUM_UNAVAILIBLE` **не** выставлен |
| батарея | 0 мВ, процент и флаги — `0xFFFFFFFF` |

Два флага, которых у эталона нет и которые мы поэтому не заявляем:
`SUPPORT_FKN` и `SUPPORT_SECURE_MESSAGING`.

**Серийник — BCD, а не двоичное число.** Печатные восемь цифр лежат по две в
байте: `47738461` → `47 73 84 61` в младших четырёх байтах. Двоичная запись
того же числа дала бы `02 D8 6E 5D` — приложение, читающее поле как BCD,
показало бы мусор. Сквозной гейт проверяет именно эту раскладку.

На эталонном устройстве оба PIN-кода сменены с заводских, отсюда оба флага
`*_PIN_NOT_DEFAULT`. У нас они выводятся косвенно, из
`CKF_TOKEN_INITIALIZED` и `CKF_USER_PIN_INITIALIZED`; прямой способ владелец
обещал дать позже, задача записана в `docs/PLAN.md`.

## Полный список функций

Состояния указаны так, как их описывает вендор.

### Идентификация и обслуживание токена

- **`C_EX_GetFunctionListExtended(ppFunctionList)`** — таблица расширения.
- **`C_EX_GetTokenInfoExtended(slotID, pInfo)`** — расширенные сведения о
  токене (см. выше).
- **`C_EX_InitToken(slotID, pPin, ulPinLen, pInitInfo)`** — полный формат
  устройства через `CK_RUTOKEN_INIT_PARAM`: оба PIN-кода, их минимальные длины,
  счётчики попыток, политика смены пользовательского PIN, метка, режим SM.
  Обычный `C_InitToken` форматирует только раздел PKCS #11.
- **`C_EX_UnblockUserPIN(hSession)`** — разблокировать пользовательский PIN.
  Условия те же, что у `C_InitPIN`.
- **`C_EX_SetTokenName(hSession, pLabel, ulLabelLen)`** — сменить метку;
  только в состоянии R/W User.
- **`C_EX_GetTokenName(hSession, pLabel, pulLabelLen)`** — прочитать метку.
- **`C_EX_SetLocalPIN(slotID, pUserPin, ulUserPinLen, pNewLocalPin, ulNewLocalPinLen, ulLocalID)`**
  — задать локальный PIN на устройствах, которые их поддерживают.
- **`C_EX_TokenManage(hSession, ulMode, pValue)`** — режимы `MODE_*`: таймаут
  выключения Bluetooth, тип канала (USB/Bluetooth), сброс PIN к стандартному
  или к заводскому, смена PIN по умолчанию, принудительная смена
  пользовательского PIN.
- **`C_EX_SlotManage(slotID, ulMode, pValue)`** — чтение: сведения о локальных
  PIN-кодах (`MODE_GET_LOCAL_PIN_INFO` → массив `CK_LOCAL_PIN_INFO`),
  информация о принудительной смене PIN (`MODE_GET_PIN_SET_TO_BE_CHANGED`),
  имитовставка (`MODE_GET_IMIT`), сброс к заводским настройкам.
- **`C_EX_GetJournal(slotID, pJournal, pulJournalSize)`** — журнал операций
  устройства.

### Лицензии

- **`C_EX_SetLicense(hSession, ulLicenseNum, pLicense, ulLicenseLen)`** —
  записать лицензию 1 или 2, длина ровно 72 байта; нужен вход как User или SO.
- **`C_EX_GetLicense(hSession, ulLicenseNum, pLicense, pulLicenseLen)`** —
  прочитать; доступно в любом состоянии.

### Сертификаты, CMS, запросы

- **`C_EX_GetCertificateInfoText(hSession, hCert, pInfo, pulInfoLen)`** —
  текстовое описание сертификата; буфер выделяет библиотека.
- **`C_EX_PKCS7Sign(...)`** — подпись данных в формате PKCS #7 вместе с
  цепочкой сертификатов. Флаги: `0` — программное хеширование, данные вложены;
  `PKCS7_DETACHED_SIGNATURE` — отделённая подпись; `USE_HARDWARE_HASH` —
  аппаратное хеширование.
- **`C_EX_PKCS7VerifyInit(hSession, pCms, ulCmsSize, pStore, ckMode, flags)`**,
  **`C_EX_PKCS7Verify(...)`**, **`C_EX_PKCS7VerifyUpdate(...)`**,
  **`C_EX_PKCS7VerifyFinal(...)`** — проверка подписи PKCS #7, одним вызовом
  или потоком. `CK_VENDOR_X509_STORE` несёт доверенные сертификаты,
  сертификаты подписантов и списки отзыва; `ckMode` задаёт строгость проверки
  CRL (`OPTIONAL_CRL_CHECK`, `LEAF_CRL_CHECK`, `ALL_CRL_CHECK`).
- **`C_EX_CreateCSR(...)`** — запрос на сертификат в формате PKCS #10. `dn`,
  `pAttributes` и `pExtensions` — массивы строк парами «тип, значение».
- **`C_EX_FreeBuffer(pBuffer)`** — освободить буфер, выделенный любой из
  функций расширения. Реализовывать вместе с первой из них, которая выделяет
  память.

### Flash-раздел (Рутокен ECP Flash)

- **`C_EX_GetVolumesInfo(slotID, pInfo, pulInfoCount)`** — разделы: номер
  (1..9), размер в МБ, режим доступа (`ACCESS_MODE_RW`, `RO`, `HIDDEN`, `CD`),
  владелец (`CKU_USER`, `CKU_SO` или локальный пользователь 3..31).
- **`C_EX_GetDriveSize(slotID, pulDriveSize)`** — ёмкость флеш-памяти в МБ.
- **`C_EX_ChangeVolumeAttributes(...)`** — сменить режим доступа к разделу,
  постоянно или до отключения от порта.
- **`C_EX_FormatDrive(...)`** — переразметить флеш-память.

### Биометрия и внешняя аутентификация

- **`C_EX_Authenticate(hSession, hAuthObject, pData, ulDataSize)`** — вход по
  объекту аутентификации.
- **`C_EX_Deauthenticate(hSession, hAuthObject)`** — выход.
- **`C_EX_UnblockAuthenticator(hSession, hAuthObject)`** — разблокировать
  объект аутентификации.

### Объявлены вендором устаревшими

Реализовывать не нужно, но в таблице они занимают свои места и порядок
остальных зависит от них: `C_EX_LoadActivationKey`,
`C_EX_SetActivationPassword`, `C_EX_GenerateActivationPassword`,
`C_EX_SignInvisibleInit`, `C_EX_SignInvisible`, `C_EX_WrapKey`,
`C_EX_UnwrapKey`.

## Вендорские коды возврата

`CKR_VENDOR_DEFINED + N`: `CKR_CORRUPTED_MAPFILE` (1),
`CKR_WRONG_VERSION_FIELD` (2), `CKR_WRONG_PKCS1_ENCODING` (3),
`CKR_RTPKCS11_DATA_CORRUPTED` (4), `CKR_RTPKCS11_RSF_DATA_CORRUPTED` (5),
`CKR_SM_PASSWORD_INVALID` (6), `CKR_LICENSE_READ_ONLY` (7),
`CKR_VENDOR_EMITENT_KEY_BLOCKED` (8), `CKR_CERT_CHAIN_NOT_VERIFIED` (9),
`CKR_INAPPROPRIATE_PIN` (10), `CKR_PIN_IN_HISTORY` (11).
