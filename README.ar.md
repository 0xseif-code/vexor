```text
 ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
 ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

**أداة استطلااف و fuzzing عالية الأداء مكتوبة بلغة Go**

[ العربية (Arabic) ] | [ English ](README.md)

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen?style=flat-square)](https://github.com/0xseif-code/vexor/releases)
[![Release](https://img.shields.io/badge/Version-1.0.0-orange?style=flat-square)](https://github.com/0xseif-code/vexor/releases)

Vexor أداة في ملف واحد (single binary) لاستكشاف الويب و fuzzing.
لا تبعيات خارجية ولا شوائب — ملف واحد وقوائم كلمات وهدف، كفى.
اختبار حقن SQLيتم عبر sqlmap.

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
| 💉 **SQLi** | اختبار حقن SQL | غلاف لـ sqlmap (المعيار الصناعي) |
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

### تحديث ذاتي

يمكن للنسخة المثبّتة ترقية نفسها من سطر الأوامر (لينكس/ماك):

```bash
vexor update --check     # مقارنة النسخة المحلية بأحدث إصدار
vexor update             # تحديث ذاتي في المكان
vexor update --force     # إعادة التثبيت حتى لو تطابقت النسختان
```

`vexor update` يحاول أولًا `go install`، ثم تنزيل ملف الإصدار
(`vexor-<os>-<arch>`)، ثم `git pull && go build` من نسخة مستنسَخة محلية.

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

### `sqli` — اختبار حقن SQL

`vexor sqli` هو غلاف لـ sqlmap — أداة حقن SQLالمعيارية في الصناعة.
Vexor لا يزوّد بمحرّك SQLi خاص به.

**لماذا sqlmap:**
- أداة مُجربة في آلاف الاختبارات
- تدعم كل قواعد البيانات والتقنيات وأنماط الحقن
- Vexor يركّز على ما يُتقنه: الاستطلااف والـ fuzzing

**المتطلبات:** يجب تثبيت sqlmap وإتاحته على PATH.

```bash
# تثبيت sqlmap
sudo apt install sqlmap          # Debian/Kali
sudo pacman -S sqlmap            # Arch
pipx install sqlmap              # pipx
```

| العلم | الاختصار | النوع | الوصف | الافتراضي |
|---|---|---|---|---|
| `--url` | `-u` | string | الهدف | |
| `--request` | `-r` | string | ملف طلب خام بصيغة Burp | |
| `--param` | `-p` | string | اختبار باراميتر واحد فقط | |
| `--database` | `-D` | string | اسم قاعدة البيانات | |
| `--table` | `-T` | string | اسم الجدول | |
| `--column` | `-C` | stringslice | أعمدة للتفريغ (قابلة للتكرار) | |
| `--data` | | string | بيانات POST | |
| `--cookie` | | string | هيدر الكوكي | |
| `--headers` | | stringarray | هيدر مخصّص (قابل للتكرار) | |
| `--proxy` | | string | بروكسي HTTP/SOCKS5 | |
| `--level` | | int | شدة الاختبار (1-5) | `1` |
| `--risk` | | int | خطورة الحمولات (1-3) | `1` |
| `--threads` | | int | طلبات متزامنة | `5` |
| `--technique` | | string | التقنيات: `BEUSTQ` | |
| `--dbms` | | string | فرض نوع قاعدة البيانات | |
| `--dbs` | | bool | سرد قواعد البيانات | `false` |
| `--tables` | | bool | سرد الجداول | `false` |
| `--columns` | | bool | سرد الأعمدة | `false` |
| `--dump` | | bool | تفريغ محتويات جدول | `false` |
| `--current-user` | | bool | سرد مستخدم DBMS الحالي | `false` |
| `--current-db` | | bool | سرد قاعدة البيانات الحالية | `false` |
| `--is-dba` | | bool | التحقق من صلاحيات DBA | `false` |
| `--passwords` | | bool | سرد هاشات كلمات المرور | `false` |
| `--batch` | | bool | وضع غير تفاعلي | `true` |
| `--random-agent` | | bool | User-Agent عشوائي | `true` |
| `--tamper` | | string | سكربت(ات) Tamper | |
| `--forms` | | bool | تحليل واختبار النماذج | `false` |
| `--crawl` | | int | عمق الزحف | `0` |
| `--os-shell` | | bool | قشرة نظام تفاعلية | `false` |
| `--sql-shell` | | bool | قشرة SQLتفاعلية | `false` |
| `--extra` | | stringslice | أرقام إضافية تمرّ مباشرة إلى sqlmap | |

```bash
# فحص أساسي
vexor sqli -u "https://target.com/page?id=1"

# سرد قواعد البيانات
vexor sqli -u "https://target.com/page?id=1" --dbs

# تفريغ جدول
vexor sqli -u "https://target.com/page?id=1" -D shop -T users --dump

# من ملف طلب خام
vexor sqli -r request.txt --dump --batch

# مع tamper ومستوى أعلى
vexor sqli -u "https://target.com/page?id=1" --tamper=space2comment --level 3
```

### `update` — تحديث الملف الثنائي ذاتيًا

```bash
vexor update --check     # مقارنة النسخة المحلية بأحدث إصدار فقط
vexor update             # تثبيت أحدث إصدار في المكان
vexor update --force     # إعادة التثبيت حتى لو تطابقت النسختان
```

يستعلم عن `https://api.github.com/repos/0xseif-code/vexor/releases/latest`
(مع الواجهة tags كبديل)، ثم يثبّت عبر `go install` أو تنزيل
`vexor-<os>-<arch>` أو إعادة بناء من المصدر — الاستراتيجية التي تنجح أولًا.

```text
$ vexor update --check
[+] Vexor is up to date: v1.0.0

$ vexor update
[*] [update] tier 1: go install github.com/0xseif-code/vexor/cmd/vexor@latest
[+] updated v1.0.0 -> v1.0.1 via go install
[i] new binary: /home/user/go/bin/vexor
[!] restart Vexor to start using the new version
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