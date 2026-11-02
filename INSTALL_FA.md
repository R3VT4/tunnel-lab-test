# نصب و آماده‌سازی GitHub — نسخهٔ ۰٫۴ آزمایشی

نام پروژه موقت است. این بسته برای آزمایش نصب و عملکرد آماده شده؛ نتیجهٔ سرعت روی اینترنت
و پایداری طولانی‌مدت هنوز مشخص نیست. پشتیبانی اجرایی فعلی Linux با systemd است.

## ۱. چه چیزی در GitHub آپلود شود؟

ZIP را باز کن و محتویات پوشهٔ tunnel-lab را در ریشهٔ مخزن قرار بده؛ README.md و go.mod
باید در صفحهٔ اصلی مخزن باشند. فایل‌های workflow را هم همراه سورس وارد کن.
صرفاً آپلودکردن خود ZIP، مخزن سورس و انتشار خودکار را راه نمی‌اندازد.

گواهی و کلید تولیدشده، پوشهٔ demo و تنظیمات واقعی سرورها را وارد مخزن نکن.
فایل اجرایی و بسته‌های آماده داخل این ZIP برای تست‌اند. bin و dist را با رابط وب GitHub آپلود نکن؛
برای مخزن، سورس کافی است و workflow فایل اجرایی می‌سازد. دستور git add با gitignore آن‌ها را کنار می‌گذارد.

روی کامپیوتری که Git دارد، از داخل پوشهٔ پروژه:

```bash
git init
git add .
git commit -m "Initial deployment test release"
git branch -M main
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

OWNER و REPOSITORY را با نام واقعی اکانت و مخزن خودت عوض کن.
اگر سورس از قبل در مخزن است، git init یا افزودن مجدد origin لازم نیست.
پس از موفقیت Checks، برای ساخت انتشار آزمایشی:

```bash
git tag v0.4.0-alpha
git push origin v0.4.0-alpha
```

workflow انتشار، بعد از بررسی‌ها یک Draft prerelease با فایل Linux amd64 و arm64 می‌سازد.
خودت در Releases پیش‌نویس را بررسی و منتشر می‌کنی؛ اینجا هنوز در اکانت تو اجرا نشده است.
workflowهای آماده به نام نهایی یا اکانت خاصی وابسته نیستند.

## ۲. تست بدون سرور

در لینوکس amd64، از ZIP سورس:

```bash
chmod +x bin/tunnellab-linux-amd64
bin/tunnellab-linux-amd64 selftest
```

یا از بستهٔ tar.gz انتشار استخراج‌شده:

```bash
./tunnellab selftest
```

تست، چند پردازش سرویس سیستم ایجاد نمی‌کند؛ موتورهای انتقال در همان برنامه، با سوکت محلی و
گواهی موقت اجرا می‌شوند. خروجی passed:true یعنی بررسی محلی موفق شده است؛ نه آماده‌بودن مسیر اینترنت.
برای خود selftest نیازی به Go، Python، root یا سرور خارجی نیست.

## ۳. دریافت و بررسی بستهٔ انتشار

بعد از انتشار پیش‌نویس، فایل مناسب معماری سرور و SHA256SUMS را از Releases بگیر.
در Ubuntu amd64 به این شکل؛ نام اکانت و مخزن نمونه است:

```bash
curl -fLO https://github.com/OWNER/REPOSITORY/releases/download/v0.4.0-alpha/tunnellab_v0.4.0-alpha_linux_amd64.tar.gz
curl -fLO https://github.com/OWNER/REPOSITORY/releases/download/v0.4.0-alpha/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
mkdir tunnel-test
tar -xzf tunnellab_v0.4.0-alpha_linux_amd64.tar.gz -C tunnel-test
cd tunnel-test
./tunnellab selftest
```

checksum خراب‌شدن یا تفاوت فایل با manifest را مشخص می‌کند؛ امضای مستقل ناشر نیست.
روی arm64 فایل متناظر arm64 را بگیر. بستهٔ arm64 اینجا cross-compile می‌شود؛ اجرای آن
روی سخت‌افزار arm64 در این محیط آزمایش نشده است.

## ۴. نصب سرویس

از پوشهٔ استخراج‌شده:

```bash
sudo bash scripts/install.sh
```

یا از سورس همراه فایل اجرایی:

```bash
sudo bash scripts/install.sh --binary ./bin/tunnellab-linux-amd64
```

نصاب کاربر و گروه tunnellab می‌سازد، فایل اجرایی را در /usr/local/bin قرار می‌دهد و
قالب سرویس systemd را نصب می‌کند. هیچ تونلی را خودکار شروع یا راه‌اندازی مجدد نمی‌کند.
پوشهٔ تنظیمات /etc/tunnellab/instances است. فایل کلید هر نمونه root:tunnellab با مجوز 0640
ذخیره می‌شود؛ پردازش سرویس با کاربر اختصاصی اجرا می‌شود، نه root.
قابلیت bind روی پورت کم‌تر از 1024 مثل 443 در قالب سرویس لحاظ شده است.
نصاب تنظیمات فایروال، SSH و مسیریابی سیستم را تغییر نمی‌دهد.

## ۵. ساخت یک جفت تنظیمات

فقط یک بار روی دستگاه امن:

```bash
tunnellab init -dir demo
```

برای ارتباط مستقیم، edge.json ورودی و relay.json سمت سرویس است؛ برای معکوس،
reverse-edge.json و reverse-relay.json را انتخاب کن. برای UDP مستقیم، فایل‌های udp را بگیر.
از هر نقش فقط فایل JSON همان حالت، گواهی و کلید همان نقش و ca.crt را به سرور مربوطه منتقل کن.
روی دو سرور جداگانه init اجرا نکن؛ گروه‌های اعتماد متفاوت می‌سازد.

آدرس‌ها و پورت‌ها را مطابق README_FA.md تغییر بده. برای نمونهٔ مستقیم:

- روی ورودی: listen آدرس دریافت مصرف‌کننده، peer آدرس سرور مقصد و پورت TLS است.
- روی سمت سرویس: listen پورت TLS و target آدرس واقعی سرویس است.
- admin باید لوپ‌بک بماند؛ برای هر نمونه پورت admin جدا تعیین کن.
- نام server_name در نمونهٔ مستقیم relay.tunnellab.local است؛ با IP مقصد جایگزین نکن.

سپس بررسی و ثبت هر سمت:

```bash
tunnellab check -config demo/edge.json
sudo tunnellab service add -name edge-one -config demo/edge.json
sudo tunnellab service start -name edge-one
```

روی سرور سمت سرویس، نام نمونه و فایل مناسب همان نقش را استفاده کن.
check فقط ساختار، جفت کلید/گواهی، اعتماد، زمان اعتبار و کاربرد گواهی خودت را بررسی می‌کند؛
بررسی اتصال به peer و target نیست.

service add گواهی‌ها را کپی می‌کند و تنظیمات مستقل می‌سازد؛ نمونهٔ موجود را بازنویسی نمی‌کند.
پورت‌های listen، tunnel_listen و admin با نمونه‌های ثبت‌شده بررسی می‌شوند؛ برای listenerهای
مدیریت‌شده IP عددی لازم است. wildcardها محافظه‌کارانه متداخل در نظر گرفته می‌شوند.
این بررسی پورت‌های نرم‌افزارهای دیگر را رزرو نمی‌کند؛ خطای bind آن‌ها در شروع سرویس مشخص می‌شود.

## ۶. مدیریت از ترمینال

```bash
sudo tunnellab service list
sudo tunnellab service status -name edge-one
sudo tunnellab service logs -name edge-one
sudo tunnellab service restart -name edge-one
sudo tunnellab service stop -name edge-one
```

start نمونه را شروع می‌کند و اجرای خودکار بعد از بوت را فعال می‌کند.
stop نمونه را می‌بندد و اجرای خودکارش بعد از بوت را غیرفعال می‌کند.
restart اتصال‌های فعال همان نمونه را قطع می‌کند؛ ارتقای بدون وقفه هنوز ساخته نشده است.
فعلاً ویرایش/حذف و rollback تنظیمات فرمان مدیریتی جدا ندارند.

برای چند تونل service add را با نام و پورت‌های جدا تکرار کن. هر نمونهٔ این نسخه یک
نگاشت پورت دارد؛ چند نگاشت یعنی چند نمونه. انتخاب خودکار بین چند مقصد هنوز پیاده نشده است.
صفحهٔ وب فعلاً وضعیت همان نمونه را نشان می‌دهد و مدیریت چند نمونه از ترمینال است.

## ۷. ارتقا و برگشت فایل اجرایی

نصاب تنظیمات موجود را دست نمی‌زند و از فایل اجرایی قبلی tunnellab.previous می‌سازد.
نسخهٔ نصب‌شدهٔ تازه فقط برای نمونه‌هایی اعمال می‌شود که بعداً شروع یا restart شوند.
برای برگشت باینری، ابتدا نمونه‌های موردنظر را stop کن، فایل قبلی را به tunnellab کپی کن
و نمونه‌ها را start کن. این backup فقط فایل اجرایی است؛ rollback کامل تنظیمات یا دیتابیس نیست.
فایل قبلی در نصب بعدی دوباره جایگزین می‌شود.

## چه چیزهایی اینجا واقعاً تست شده‌اند؟

نصب در یک ریشهٔ موقت، بدون اجرای systemctl یا ساخت کاربر سیستم آزمایش می‌شود.
قالب systemd آماده شده، اما بوت و راه‌اندازی واقعی سرویس روی میزبان systemd هنوز باید
روی سرور آزمایشی تو بررسی شود. آزمون GitHub Actions نیز بعد از آپلود در اکانت تو انجام می‌شود.
برای گزارش مشکل: نسخه، توزیع/معماری، حالت تونل، خطای check و لاگ همان نمونه کافی است؛
کلید خصوصی و لینک حاوی اطلاعات اتصال را در Issue عمومی قرار نده.
