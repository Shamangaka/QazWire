# QazWire — архитектура жизненного цикла криптографических ключей (KLM), R2

**Статус:** DESIGN DRAFT / NOT IMPLEMENTED. Интерфейсы и инварианты для будущей реализации. **В WireGuard не внедряется** (задание R2). Код ниже — эскиз для рецензии, не для копирования в `device/*`.
**Дата:** 2026-11-02. Ссылки на код — `master` @ `b3bc704`.

## 1. Исходное состояние в wireguard-go и проблемы

| Место | Поведение | Проблема для QazWire |
| --- | --- | --- |
| `device/keypair.go:24–33` | `Keypair{send, receive cipher.AEAD; sendNonce atomic.Uint64; replayFilter ...}` | Ключ спрятан внутри `cipher.AEAD`; нет состояния «уничтожен», нет учёта блоков |
| `device/keypair.go:48–52` `DeleteKeypair` | Только удаляет индекс | Ключевой материал не стирается (признано в `keypair.go:17–22`) |
| `device/noise-protocol.go:682–705`, `:710–727` | Ротация previous/current/next | Удаление `previous` при наличии ссылок из очередей |
| `device/send.go:337–360`, `:439–475` | Пакеты получают `elem.keypair` при постановке в очередь; шифрование — позже в рабочих потоках | Если стереть ключ сразу при ротации, рабочий поток зашифрует пакеты **обнулёнными раундовыми ключами** и отправит их (QW-R1-F09) |
| `device/receive.go:238–266` | Расшифрование в рабочих потоках по `elem.keypair` | Аналогично для `Open` |
| `device/peer.go:214–238` `ZeroAndFlushAll`, `device/timers.go:126–129` | «Удаление всех ключей» | Без стирания |
| `device/noise-types.go:27–37` `loadExactHex` | `hex.DecodeString` → копия → временный срез не стирается; исходная строка UAPI неизменяема | Остаточные копии static-ключа и PSK |
| `device/uapi.go:89`, `:104` | `get` возвращает private key и PSK | Лишняя экспозиция |

## 2. Требования (из R1/R2 и СТ РК 1073-2025)

- §5.1.4: один ключ — один алгоритм — одна цель.
- §5.3.9 / 5.4.11 / 5.5.12 / 5.6.12: уничтожение ключей после использования (или орг.-тех. меры).
- §5.5.13 / 5.6.13: аварийное уничтожение.
- `SECURITY_BOUNDS_R2` §7.3: учёт σ_e, σ_tag, σ_ver, q_v на ключ с мягкими и жёсткими лимитами.
- `CONSTRUCTION_REVIEW_R2` §2.2: запрет контрольных значений e_K(0^n) на MAC-ключах.

## 3. Модель объектов

```
SessionKeys (одна пара после handshake; epoch = уникальный номер)
 ├── SendKeys  (направление «я → пир»):  K_e, K_m, K_m′ + счётчик пакетов c + σ_e, σ_tag
 └── RecvKeys  (направление «пир → я»):  K_e, K_m, K_m′ + replay-окно + σ_ver, q_v
Каждый ключ внутри — KeySlot{profile, dir, purpose, epoch, blen, klen, material, roundKeys}
```

Неизменяемые атрибуты KeySlot: (ProfileID, Direction, Purpose ∈ {CTR, MAC_K, MAC_K′}, Epoch, Blen, Klen). Материал хранится в одном месте и не копируется.

## 4. Интерфейсы (эскиз Go)

```go
//go:build qazwire_exp

package qwkeys

type Purpose uint8   // PurposeCTR, PurposeMACK, PurposeMACKPrime
type Direction uint8 // DirInitToResp, DirRespToInit

// Limits — из профиля (SECURITY_BOUNDS_R2 §7.3). Нули запрещены.
type Limits struct {
    RekeyAfterMessages, RejectAfterMessages uint64
    RekeyAfterBlocks,   RejectAfterBlocks   uint64 // σ_e (CTR), отправитель
    MaxTagBlocks                            uint64 // σ_tag, отправитель
    MaxVerifyBlocks                         uint64 // σ_ver (все проверки), получатель
    MaxFailedVerifications                  uint64 // q_v, получатель
}

// Deriver — единственный способ создать ключи. master обнуляется в любом исходе.
type Deriver interface {
    DeriveSend(p ProfileID, epoch uint64, dir Direction, master *[32]byte) (*SendKeys, error)
    DeriveRecv(p ProfileID, epoch uint64, dir Direction, master *[32]byte) (*RecvKeys, error)
}

// SendKeys / RecvKeys — непрозрачные; копирование запрещено (noCopy + vet).
type SendKeys struct{ noCopy noCopy; st state; /* KeySlot x3, counters */ }
type RecvKeys struct{ noCopy noCopy; st state; /* KeySlot x3, replay, counters */ }

// Lease — доказательство владения ссылкой; обязателен для любой операции.
type SendLease struct{ k *SendKeys }
type RecvLease struct{ k *RecvKeys }

func (k *SendKeys) Acquire() (SendLease, error) // ErrRetired / ErrDestroyed
func (k *RecvKeys) Acquire() (RecvLease, error)

// Reserve атомарно резервирует счётчик (единый источник) с проверкой SEAL_OFF и лимитов.
// CounterTicket одноразовый, с неэкспортируемыми полями, привязан к (ключ, epoch);
// вызывающий не может подставить свой счётчик. Мягкий лимит → rekeyHint=true.
func (l SendLease) Reserve() (tk CounterTicket, rekeyHint bool, err error) // ErrExhausted, ErrRetired

// Seal пишет H (счётчик берётся из билета), шифрует и вырабатывает тег.
// Повторное использование билета или билет другого ключа → ошибка.
func (l SendLease) Seal(dst []byte, receiver uint32, tk CounterTicket, pt []byte) (pkt []byte, err error)

// Open: проверка MAC до CTR; при ошибке dst не содержит открытого текста.
// Окно повторов обновляется ТОЛЬКО после успешной проверки (внутри Open или отдельным Commit).
func (l RecvLease) Open(dst []byte, hdr *[16]byte, ctTag []byte) (pt []byte, ctr uint64, err error)

func (l SendLease) Release()
func (l RecvLease) Release()

func (k *SendKeys) Retire()  // новые Acquire запрещены; Seal по существующим Lease — ошибка
func (k *RecvKeys) Retire()  // новые Acquire запрещены, Open по существующим Lease разрешён
func (k *SendKeys) Destroy() // Retire + сброс ссылки владельца; стирание при refs == 0
func (k *RecvKeys) Destroy()
```

## 5. Конечный автомат и счётчик ссылок

Состояние и счётчик ссылок хранятся в **одном** атомарном 64-битном слове, чтобы переходы были линеаризуемы:

```
bit 63: RETIRED   (новые Acquire запрещены)
bit 62: SEAL_OFF  (Seal запрещён даже по существующим Lease; для SendKeys = RETIRED)
bit 61: DESTROYED (материал стёрт)
bits 0..60: refs  (1 ссылка владельца + число Lease)
```

| Переход | Операция |
| --- | --- |
| Создание | refs = 1 (владелец), флаги = 0 |
| Acquire | CAS-цикл: если RETIRED или DESTROYED → ошибка; иначе refs+1 |
| Release | `Add(−1)`; если результат == (RETIRED, refs = 0) → стереть материал, установить DESTROYED |
| Retire | `Or(RETIRED[\|SEAL_OFF])` |
| Destroy | Retire, затем Release ссылки владельца (однократно; повторный Destroy — no-op через отдельный флаг владельца) |

Почему одно слово: при раздельных `state` и `refs` возможна гонка «Acquire прочитал Active → Destroy установил Retired и снял владельца → Acquire увеличил refs», то есть выдача Lease на выводимый из употребления ключ. CAS по единому слову её исключает.

## 6. Инварианты безопасности (проверяемые)

| ID | Инвариант | Как обеспечивается | Тест |
| --- | --- | --- | --- |
| KL-1 | Операция над ключом возможна только при действующем Lease | Методы только у `*Lease`; у ключей нет публичных методов `Seal/Open` | Компиляция + ревью экспортов |
| KL-2 | Ни одна операция не выполняется над стёртым материалом | Стирание только при refs = 0; DESTROYED проверяется в Seal/Open | T-KLM-01 (стресс ротации с `-race`), T-REKEY-01 |
| KL-3 | После Retire отправитель не шифрует новые пакеты | SEAL_OFF проверяется атомарно перед назначением счётчика | T-KLM-02 |
| KL-4 | Счётчик пакета уникален на ключ и не сбрасывается | Счётчик внутри SendKeys; `Add`; при достижении RejectAfterMessages → SEAL_OFF; ключи не сериализуются | T-NX-04 |
| KL-5 | Учёт объёма обязателен | Seal увеличивает σ_e, σ_tag; Open — σ_ver (по всем проверкам), q_v (по отказам); превышение жёсткого лимита → Retire + сигнал handshake | T-KLM-03 |
| KL-6 | Разделение ключей | Deriver выводит каждый KeySlot с уникальной меткой (профиль, направление, назначение); при создании проверяется попарное различие; повторное использование KeySlot в другом назначении невозможно (поле purpose неизменяемо) | T-PROP-05, T-NEG-10, T-XP-08/09 |
| KL-7 | Нет контрольных значений e_K(0^n) на MAC-ключах | API не предоставляет «прямого» шифрования блока | Ревью API |
| KL-8 | Нет экспорта ключей | Нет геттеров; `String()/GoString()/Format` печатают только (profile, epoch, purpose); UAPI `get` не выдаёт секреты | T-KLM-04 |
| KL-9 | Утечка Lease обнаруживается | В тестовой сборке: после `ZeroAndFlushAll` и опустошения очередей refs всех ключей = 0, иначе тест падает | T-KLM-05 |
| KL-10 | Аварийное уничтожение не создаёт окна шифрования на стёртом ключе | Сначала остановка отправки (`device.Down()`: закрыть bind, остановить рабочие потоки), затем немедленное стирание независимо от refs | T-KLM-06 |
| KL-11 | Не более одного «текущего» SendKeys на пира | Ротация под мьютексом `Keypairs` (как `noise-protocol.go:682–705`), Retire старого до публикации нового | T-KLM-02 |

## 7. Параллелизм и ротация (сопоставление с потоками wireguard-go)

| Этап wireguard-go | Действие KLM |
| --- | --- |
| `SendStagedPackets` (`send.go:337–360`): выбор `current`, назначение nonce | `Acquire` → Lease. Счётчик можно по-прежнему назначать при постановке в очередь (это сохраняет порядок отправки), но только через метод Lease, который атомарно проверяет SEAL_OFF и лимиты. Назначенный, но не использованный счётчик **не переиспользуется**. Если Seal возвращает ErrRetired/ErrExhausted, пакет повторно ставится в staged-очередь на новый ключ и запускается handshake |
| `RoutineEncryption` (`send.go:439–475`) | `lease.Seal(...)`; затем `lease.Release()` — **во всех путях**, включая ошибку |
| `FlushStagedPackets`, закрытие очередей | `Release` для каждого элемента с Lease |
| `RoutineReceiveIncoming` (`receive.go:153–166`): lookup по индексу | `Acquire` на RecvKeys; при ErrDestroyed — отбросить |
| `RoutineDecryption` (`receive.go:238–266`) | `lease.Open` (MAC → CTR); при ошибке — `nil` |
| `RoutineSequentialReceiver` (`receive.go:449–455`) | Окно обновляется только для пакетов, прошедших Open; затем `Release` |
| Ротация (`BeginSymmetricSession`, `ReceivedWithKeypair`) | Новый ключ публикуется; старый Send → `Retire`; старый Recv остаётся для приёма до `RejectAfterTime`; `DeleteKeypair` → `Destroy` |
| `expiredZeroKeyMaterial` (`timers.go:126–129`) | `Destroy` всех ключей пира |
| Аварийное уничтожение (новое, UAPI `zero_all_keys=true`, TBD) | `device.Down()` → `Destroy` + немедленное стирание (KL-10) → стирание static, PSK, `precomputedStaticStatic` |

Стоимость: Acquire/Release — по одному CAS/Add на пакет. Для уменьшения конкуренции за кэш-линию возможны пакетные Lease (один Acquire на пакетную очередь `elemsContainer`) — PENDING (бенчмарк T-PERF).

## 8. Best-effort затирание в Go

Гарантий нет (признано в `keypair.go:17–22`). Меры по убыванию значимости:

1. **Один владелец материала.** Ключи и раундовые ключи — массивы фиксированного размера в одной куче-аллокации (`new(KeySlot)`), только указатели и `noCopy`. Нет преобразований в `string`, нет передачи по значению.
2. **Стирание:** `clear(slot.material[:])`, `clear(slot.roundKeys[:])`, затем `runtime.KeepAlive(slot)`. Запись в достижимую через указатель память кучи компилятор не удаляет. Сборщик мусора gc в текущей реализации не перемещает объекты кучи, но спецификация Go этого не гарантирует → зафиксировать версию тулчейна в ТД.
3. **Стек.** Локальные массивы с секретами (как `var key [32]byte` в `noise-protocol.go:302`, `:359`, `:491`) могут копироваться при росте стека, и старые копии не стираются. Мера — держать промежуточные секреты в KeySlot/скретч-объекте в куче. В Go 1.26 появился экспериментальный пакет `runtime/secret` (`GOEXPERIMENT=runtimesecret`): `secret.Do(f)` стирает регистры и стек, использованные f, а новые аллокации кучи — после того как GC признает их недостижимыми. Модуль сейчас — `go 1.23.1`; переход и эксперимент — PENDING.
4. **Отдельная «секретная арена» вне кучи Go.** `unix.Mmap` + `unix.Mlock` (не попадает в swap) + `madvise(MADV_DONTDUMP)` (не попадает в core dump) + охранные страницы; ключи живут только там. Это снимает зависимость от GC, но требует `unsafe` и дисциплины. Вариант — PENDING (решение владельца).
5. **Процесс:** `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE = 0`, логирование без секретов.
6. **Конфигурация:** разбирать ключи из `[]byte`-буфера с последующим стиранием; `loadExactHex` (`noise-types.go:27–37`) — заменить на декодирование в фиксированный массив без промежуточного среза. Строки UAPI неизменяемы: остаточные копии в них неизбежны → документировать (BR-07).

Статус: **PENDING**; остаточные ограничения — обязательный раздел ЭД (§5.2.3 СТ РК 1073-2025).

## 9. Вариант с Rust-провайдером через FFI (QazInfraCrypto)

| Аспект | Решение |
| --- | --- |
| Владелец ключей | Rust; ключи живут в памяти Rust (mlock, `zeroize` в `Drop`), Go видит только непрозрачный дескриптор `(index, generation)` |
| Дескрипторы | Таблица слотов с номерами поколений: устаревший дескриптор → ошибка (нет use-after-free и ABA) |
| Состояние и ссылки | В Rust: `Arc<KeySet>` + атомарное слово состояния (как §5); Lease = инкремент на время вызова или пакетного вызова |
| API | `qic_derive(profile, epoch, dir, master_ptr, 32, out_handle) → i32` (Go стирает master сразу после вызова); `qic_seal_batch(handle, items_ptr, n) → i32`; `qic_open(handle, hdr16, ct, ct_len, out, out_cap, out_len) → i32`; `qic_retire`, `qic_destroy`, `qic_zero_all` |
| Ошибки | Только коды; `catch_unwind` на каждой `extern "C"` функции либо `panic = "abort"` (fail-closed) |
| Указатели Go | Используются только на время вызова (правила cgo: C не хранит указатели Go после возврата); Rust не сохраняет их |
| Производительность | Накладные расходы cgo на вызов существенны для пакетов → только пакетный API; бенчмарк — T-PERF |
| Граница модуля | Rust-библиотека = кандидат на оцениваемую границу СКЗИ (ADR-0002 QazInfraCrypto); Go — недоверенный вызывающий |
| Сборка | Статическая библиотека, закреплённый тулчейн, воспроизводимость; `#![forbid(unsafe_code)]` везде, кроме FFI-шима |
| Риски | Сложность сборки; два рантайма; паники; отладка. Преимущество — управляемое затирание и единая реализация для всех продуктов |

## 10. Аварийное и плановое уничтожение — последовательности

**Плановая ротация (send):**
1. Handshake завершён → `DeriveSend` (новый epoch).
2. Под мьютексом пира: старый `Retire` (SEAL_OFF), новый публикуется как current.
3. Пакеты со старым Lease, ещё не прошедшие Seal, получают ErrRetired → повторно ставятся в очередь на новый ключ.
4. Старый `Destroy` при удалении из previous → стирание при refs = 0.

**Аварийная:**
1. Перевести устройство в Down (закрыть bind, остановить рабочие потоки, очистить очереди).
2. Для всех пиров: `Destroy` с принудительным стиранием (отправка невозможна → KL-10).
3. Стереть static-ключ, PSK, `precomputedStaticStatic`, cookie-секреты.
4. Зарегистрировать событие (без секретов); дальнейший запуск — только с новой конфигурацией.

## 11. Тесты KLM (добавлены в матрицу R2)

T-KLM-01 … T-KLM-06 и T-XP-08/09 — см. `QAZWIRE_TEST_MATRIX_R1.md` §13 (обновление R2).

## 12. Статусы

| Элемент | Статус |
| --- | --- |
| Модель объектов, автомат, инварианты KL-1…KL-11 | PENDING (рецензия) |
| Затирание в Go | PENDING; полнота недостижима — документируемое ограничение (BR-07) |
| Rust-FFI вариант | PENDING (решение владельца, G4 спецификации) |
| Внедрение в `device/*` | **Не выполнялось**; запрещено до G-Q1…G-Q7 (`QAZWIRE_AUDIT_R2.md` §5) |
