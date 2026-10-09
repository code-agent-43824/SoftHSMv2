# OpenSSL из portable test-kit: практическое руководство

Это руководство лежит рядом с `README.txt` **в распакованном test-kit** для
Linux x64/ARM64, macOS universal и Windows x86/x64/ARM64. Все пути ниже
относительны к корню этого каталога. Комплектный OpenSSL — отдельный
криптографический инструмент и независимый проверяющий для SoftHSM; команды
OpenSSL сами по себе **не обращаются к PKCS #11-токену**. Для проверки ключа
токена сначала получите открытый ключ или подпись через PKCS #11, либо
запустите `run-test.sh` / `run-test.cmd` и используйте его файлы
`test-output`.

## Что входит в комплект

- `bin/openssl` или `bin/openssl.exe`, локальные разделяемые библиотеки
  OpenSSL, `bin/gostprov.*` и `bin/gost.*`;
- `config/openssl.cnf` — штатная конфигурация, используемая тестами RSA,
  X.509 и CMS; `config/openssl-gost.cnf` — включение сразу `default` и
  `gostprov` для обычных команд с ГОСТ; `config/openssl-gost-engine.cnf`
  включает legacy ENGINE для ГОСТ CMS/PKCS#7;
- `ENVIRONMENT.txt` и `testkit.env` — версии инструментов и платформы;
  `scripts/verify-gost-openssl.sh` или `.ps1` — готовые проверки.

Не заменяйте комплектный `bin/openssl` системным бинарником: версия,
провайдер и локальная `libcrypto` должны соответствовать друг другу. Не
переносите отдельно `gostprov` без библиотек из того же архива.

## Запуск на Linux и macOS

Откройте терминал в корне распакованного архива. Функция ниже задаёт
переменные **только на время одной команды OpenSSL**:

```bash
KIT="$(pwd)"
gost() {
  OPENSSL_CONF="$KIT/config/openssl-gost.cnf" \
  OPENSSL_MODULES="$KIT/bin" "$KIT/bin/openssl" "$@"
}
mkdir -p my-openssl
gost version
gost list -providers
gost list -digest-algorithms
gost list -cipher-algorithms
```

На Linux/macOS это работает из любого текущего каталога после определения
`KIT` абсолютным путём. Если ZIP-распаковщик сбросил бит исполнения, сначала
выполните `chmod +x bin/openssl`; обычный `run-test.sh` тоже восстанавливает
необходимые биты. В списке провайдеров должны быть `default` и `gostprov`.

## Запуск на Windows PowerShell

Откройте **отдельное окно PowerShell** в корне test-kit:

```powershell
$Kit = (Resolve-Path .).Path
$OpenSSL = Join-Path $Kit 'bin/openssl.exe'
$env:OPENSSL_CONF = Join-Path $Kit 'config/openssl-gost.cnf'
$env:OPENSSL_MODULES = Join-Path $Kit 'bin'
$Work = Join-Path $Kit 'my-openssl'
New-Item -ItemType Directory -Force $Work | Out-Null
& $OpenSSL version
& $OpenSSL list -providers
& $OpenSSL list -digest-algorithms
& $OpenSSL list -cipher-algorithms
```

Во всех дальнейших командах заменяйте `gost` на `& $OpenSSL` и Unix-пути
на `Join-Path`/Windows-пути. Несколько готовых примеров:

```powershell
[IO.File]::WriteAllBytes((Join-Path $Work 'message.bin'),
    [Text.Encoding]::UTF8.GetBytes('portable OpenSSL example'))
& $OpenSSL dgst -md_gost12_256 -binary -out (Join-Path $Work 'streebog256.bin') (Join-Path $Work 'message.bin')
& $OpenSSL genpkey -algorithm gost2012_256 -pkeyopt paramset:A -out (Join-Path $Work 'gost256.pem')
& $OpenSSL pkey -in (Join-Path $Work 'gost256.pem') -pubout -out (Join-Path $Work 'gost256.pub.pem')
& $OpenSSL dgst -md_gost12_256 -sign (Join-Path $Work 'gost256.pem') -out (Join-Path $Work 'gost256.sig') (Join-Path $Work 'message.bin')
& $OpenSSL dgst -md_gost12_256 -verify (Join-Path $Work 'gost256.pub.pem') -signature (Join-Path $Work 'gost256.sig') (Join-Path $Work 'message.bin')
& $OpenSSL enc -magma-ctr-acpkm -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -iv 00112233 -in (Join-Path $Work 'message.bin') -out (Join-Path $Work 'magma.bin')
```

Из этого окна запускайте только независимый OpenSSL. Переменные окружения
здесь остаются до закрытия окна: **не запускайте в нём**
`softhsm2-util`/`softhsm2-export` с ГОСТ-конфигом. Эти утилиты имеют
собственную статически связанную криптобиблиотеку. `run-test.cmd` сам
ограничивает действие ГОСТ-конфига отдельными вызовами OpenSSL.

## Хеши: Стрибог и обычный SHA-256

```bash
printf '%s' 'portable OpenSSL example' > my-openssl/message.bin
gost dgst -md_gost12_256 my-openssl/message.bin
gost dgst -md_gost12_512 my-openssl/message.bin
gost dgst -sha256 my-openssl/message.bin
gost dgst -md_gost12_256 -binary -out my-openssl/streebog256.bin my-openssl/message.bin
```

Без `-binary` результат — читаемая hex-строка; с ним — сырые 32/64 байта.
Тест сравнивает такие байты с `test-output/gost-pkcs11/digest256.bin` и
`digest512.bin`, полученными через PKCS #11. Не добавляйте перевод строки
к сообщению при повторении контрольного значения: `printf '%s'` и
`echo` хешируют разные данные.

## Ключи ГОСТ, подпись и проверка

Эти команды **генерируют отдельные ключи OpenSSL**, не ключи токена:

```bash
gost genpkey -algorithm gost2012_256 -pkeyopt paramset:A -out my-openssl/gost256.pem
gost genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out my-openssl/gost512.pem
gost pkey -in my-openssl/gost256.pem -pubout -out my-openssl/gost256.pub.pem
gost dgst -md_gost12_256 -sign my-openssl/gost256.pem \
  -out my-openssl/gost256.sig my-openssl/message.bin
gost dgst -md_gost12_256 -verify my-openssl/gost256.pub.pem \
  -signature my-openssl/gost256.sig my-openssl/message.bin
```

Для 512 бит замените `256` на `512` во всех именах и в `-md_gost12_512`.
Успешная проверка печатает `Verified OK`; при неверной подписи или
изменённом сообщении OpenSSL возвращает ненулевой код. Подписи — бинарные
файлы, не PEM. Подпись рандомизирована: сравнивайте результат проверки,
не байты двух заново созданных подписей. `paramset:A` — конкретный набор
параметров провайдера; нельзя считать все кривые с одинаковой длиной ключа
взаимозаменяемыми.

После `run-test.sh` или `run-test.cmd` можно проверить **подпись,
действительно созданную SoftHSM**, без доступа к его закрытому ключу:

```bash
gost pkey -pubin -inform DER -in test-output/gost-pkcs11/public256.der \
  -out my-openssl/softhsm-public256.pem
gost dgst -md_gost12_256 -verify my-openssl/softhsm-public256.pem \
  -signature test-output/gost-pkcs11/signature256.bin \
  test-output/gost-pkcs11/message.bin
```

Есть также `public512.der`, `signature512.bin`,
`message512.bin`; для них используйте `-md_gost12_512`. Для
256-битного ключа доступны `signature256-multipart.bin` и
`signature256-paramset.bin`. Команда `pkey -pubin -inform DER`
превращает DER SubjectPublicKeyInfo токена в PEM. Сырые PKCS #11
`CKA_EC_POINT`/подпись и PEM/DER — разные форматы; не подавайте сырые
координаты напрямую как `-verify`-ключ.

В `test-output/exported-gost.der` после bundled-сценария лежит
PKCS #8 **закрытый** ключ, экспортированный специальной отладочной
утилитой. Только для локального тестового токена:

```bash
gost pkey -inform DER -in test-output/exported-gost.der \
  -out my-openssl/exported-gost.pem
gost pkey -in my-openssl/exported-gost.pem -pubout \
  -out my-openssl/exported-gost.pub.pem
gost asn1parse -inform DER -in test-output/exported-gost.der
```

Не публикуйте `test-output`, PEM закрытого ключа и содержимое
`my-openssl`; `softhsm2-export` преднамеренно игнорирует атрибуты
`SENSITIVE/NON_EXTRACTABLE` тестового токена.
`asn1parse` показывает структуру и OID, но само по себе не проверяет
правильность подписи — для неё используйте `dgst -verify`.

## Кузнечик и Магма: CTR / CTR-ACPKM

`-K` — **64 hex-символа** (32 байта ключа), `-iv` — начальное значение:
16 hex-символов (8 байт) для Кузнечика и 8 hex-символов (4 байта) для Магмы
в этих режимах. Например:

```bash
gost enc -kuznyechik-ctr-acpkm \
  -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  -iv 0011223344556677 -in my-openssl/message.bin \
  -out my-openssl/kuznyechik.bin
gost enc -d -kuznyechik-ctr-acpkm \
  -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  -iv 0011223344556677 -in my-openssl/kuznyechik.bin \
  -out my-openssl/decrypted.bin
```

Замените режим на `-magma-ctr-acpkm`, IV на `00112233` для Магмы.
Также проверены `-kuznyechik-ctr` и `-magma-ctr`. Воспроизведение
короткого шифротекста токена использует бинарные ключ и IV из
`test-output/gost-pkcs11/`. В PowerShell их можно получить в hex так:
`[Convert]::ToHexString(...)` доступен не во всех версиях PowerShell;
совместимый вариант — `[BitConverter]::ToString([IO.File]::ReadAllBytes($Path)).Replace('-', '')`.

`openssl enc` не задаёт длину секции смены ключа ACPKM, поэтому в тесте
его результат сравнивается с **первыми 32 байтами** шифротекста SoftHSM.
Длинные потоки после смены ключа проверяются отдельными эталонными
векторами устройства, а не этой командой. CTR/CTR-ACPKM не аутентифицируют
сообщение; совпавшая расшифровка не доказывает его целостность.

## ГОСТ CMS/PKCS#7 через локальный ENGINE

`gostprov` обслуживает `dgst`, `genpkey` и шифры. В OpenSSL 3.5.8
`smime -sign`/`cms -sign` с одним provider-ключом не выбирают legacy
signature NID. Для этих двух команд test-kit дополнительно содержит ENGINE
`bin/gost.so` (`gost.dylib`/`gost.dll`) из того же закреплённого исходника.
Его отдельный конфиг не меняет штатный provider-режим:

```bash
cms_gost() {
  OPENSSL_CONF="$KIT/config/openssl-gost-engine.cnf" \
  OPENSSL_ENGINES="$KIT/bin" OPENSSL_MODULES="$KIT/bin" \
    "$KIT/bin/openssl" "$@"
}
bash "$KIT/scripts/verify-gost-cms.sh" "$KIT"
cms_gost smime -sign -md streebog256 -binary -nodetach \
  -in "$KIT/test-output/gost-cms/message.txt" \
  -signer "$KIT/test-output/gost-cms/ca.pem" \
  -inkey "$KIT/test-output/gost-cms/key.pem" \
  -outform DER -out "$KIT/test-output/gost-cms/manual.der"
cms_gost smime -verify -inform DER \
  -in "$KIT/test-output/gost-cms/manual.der" \
  -CAfile "$KIT/test-output/gost-cms/ca.pem" \
  -out "$KIT/test-output/gost-cms/manual-verified.txt"
```

Self-тест также проверяет `cms -sign/-verify`, OID ГОСТ в DER и полное
совпадение исходного сообщения. CA в нём имеет
`basicConstraints=critical,CA:TRUE`. Для Windows выполните
`scripts/verify-gost-cms.ps1 -KitDir $Kit`: скрипт сам задаёт локальные
`OPENSSL_CONF`, `OPENSSL_ENGINES` и `OPENSSL_MODULES` только на время теста.

При доступе к **физическому** Рутокену есть отдельный кросс-тест. Он
проверяет A: envelope OpenSSL → `pkcs11-tool --rutoken-pkcs7-verify` с
`--rutoken-trusted`; затем B: `C_EX_PKCS7Sign` на токене →
`openssl smime -verify -CAfile`. Нужны ID сертификата на токене и PEM его
CA с `basicConstraints=critical,CA:TRUE`. Например, на Unix:

```bash
read -r -s -p 'Rutoken PIN: ' RUTOKEN_PIN; printf '\n'; export RUTOKEN_PIN
bash "$KIT/scripts/verify-rutoken-cms-cross.sh" "$KIT" \
  /path/to/vendor-pkcs11.so 0 0102 /path/to/token-ca.pem
unset RUTOKEN_PIN
```

На Windows используйте `scripts/verify-rutoken-cms-cross.ps1` с параметрами
`-KitDir`, `-Module`, `-Slot`, `-CertificateId`, `-TokenCaPem`; PIN задаётся
в `RUTOKEN_PIN`. Утилита получает его как `--pin env:RUTOKEN_PIN`, без
значения PIN в командной строке. Программный `FAKE_RUTOKEN_ECP` поддерживает
`C_EX_PKCS7Sign/Verify` для RSA/SHA-256 и ГОСТ 2012/256/512. Его проверки
не заменяют сравнение с физическим устройством.

После `run-test.sh`/`run-test.cmd` battery сохраняет ГОСТ-конверты в
`test-output/battery/run-1/cms` (256 бит) и `cms-gost512` (512 бит):
`gost-attached.der`, `gost-detached.der`, `gost-root.der`,
`gost-signer.der`, `gost-content.bin`. Комплектный OpenSSL проверяет
конверт модуля независимо от его PKCS #11 реализации:

```bash
CASE="$KIT/test-output/battery/run-1/cms"
cms_gost x509 -inform DER -in "$CASE/gost-root.der" -out "$CASE/gost-root.pem"
cms_gost smime -verify -inform DER -in "$CASE/gost-attached.der" \
  -CAfile "$CASE/gost-root.pem" -out "$CASE/recovered.bin"
cmp "$CASE/gost-content.bin" "$CASE/recovered.bin"
```

Для 512 бит замените `cms` на `cms-gost512`. Штатная battery также проверяет
обратное направление: конверт OpenSSL с signed attributes модуль проверяет
через `C_EX_PKCS7Verify`. Межплатформенная матрица обменивается конвертами
Linux ↔ Windows для обоих размеров. Для физического Рутокена всё ещё нужна
отдельная аппаратная проверка.

## RSA, сертификаты и CMS

Эти команды использует тот же функциональный сценарий. Для RSA/X.509/CMS
используйте штатный `config/openssl.cnf`: в нём сохранены настройки
расширений сертификатов, отсутствующие в минимальном ГОСТ-конфиге. На
Linux/macOS определите отдельную функцию:

```bash
ossl() { OPENSSL_CONF="$KIT/config/openssl.cnf" "$KIT/bin/openssl" "$@"; }
```

На Windows в **отдельном окне PowerShell** задайте
`$env:OPENSSL_CONF = Join-Path $Kit 'config/openssl.cnf'`, затем запускайте
`& $OpenSSL ...`. Везде ниже `ossl` означает этот штатный режим.
Пример для уже созданного `run-test` каталога:

```bash
ossl req -in test-output/request.pem -verify -noout
ossl x509 -in test-output/issued.pem -noout -subject -issuer
ossl verify -CAfile test-output/ca.pem test-output/issued.pem
ossl x509 -in test-output/issued.pem -outform DER -out my-openssl/issued.der
ossl cms -verify -binary -inform DER \
  -in test-output/signature.p7s -content test-output/payload.bin \
  -CAfile test-output/ca.pem -purpose any -out my-openssl/verified.bin
ossl pkey -in test-output/exported-rsa.pem -pubout \
  -out my-openssl/exported-rsa.pub.pem
```

`req -verify` проверяет самоподпись CSR, `verify` — цепочку сертификата,
`cms -verify` — подпись detached CMS с отдельно переданным `-content`.
Файл `verified.bin` должен побайтно совпасть с `payload.bin`.
`-purpose any` в тесте не заменяет проверку назначения сертификата в
реальном приложении. Для собственного **одноразового тестового** CA и CSR,
уже созданного тестом, повторите:

```bash
ossl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=Portable PKCS11 Test CA' \
  -keyout my-openssl/ca.key -out my-openssl/ca.pem
ossl x509 -req -in test-output/request.pem -CA my-openssl/ca.pem \
  -CAkey my-openssl/ca.key -CAcreateserial -days 1 -sha256 \
  -out my-openssl/issued.pem
ossl verify -CAfile my-openssl/ca.pem my-openssl/issued.pem
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out my-openssl/ec.pem
ossl pkey -in my-openssl/ec.pem -check -noout
```

`-nodes` оставляет ключ CA без шифрования — здесь это только короткоживущий
тестовый файл, не шаблон для производственного CA. `pkey -check`
проверяет структуру импортированного/созданного закрытого ключа, но не
связывает его с токеном. Готовые точные вызовы, включая выдачу сертификата
и CMS, есть в `scripts/run-pkcs11-integration.sh`/`.ps1`.

## Где искать подсказки и как разбирать ошибки

- `gost help`, `gost dgst -help`, `gost pkey -help`,
  `gost enc -help`, `gost list -providers -verbose` показывают
  возможности именно этой сборки; версия и сборочное окружение — в
  `ENVIRONMENT.txt` и выводе `gost version -a`.
- `Provider gostprov not found` или `unsupported`: проверьте абсолютные
  `OPENSSL_CONF` и `OPENSSL_MODULES`, а также совместный вывод
  `list -providers`. Одного системного OpenSSL недостаточно.
- `Unable to load key`/ошибка проверки: проверьте `DER` против `PEM`,
  256 против 512 бит, параметр кривой и точные байты сообщения.
- Полная автоматическая самопроверка провайдера: `bash
  scripts/verify-gost-openssl.sh "$KIT"` на Unix после
  `export OPENSSL_CONF="$KIT/config/openssl-gost.cnf"` и
  `export OPENSSL_MODULES="$KIT/bin"` **в отдельном терминале**, либо
  `powershell -File scripts/verify-gost-openssl.ps1 -KitDir $Kit` на
  Windows после установки двух переменных из начала руководства.
  Полный `run-test.sh`/`run-test.cmd` дополнительно проверяет
  реальные результаты SoftHSM через PKCS #11.

Это руководство описывает **проверенные интерфейсы данного архива**, а не
полный каталог OpenSSL или обещание равенства всех механизмов PKCS #11.
