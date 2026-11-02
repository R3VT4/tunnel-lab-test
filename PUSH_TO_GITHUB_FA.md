# انتقال کامل پروژه به GitHub از Windows PowerShell

این بسته فقط سورس است؛ فایل اجرایی لینوکس و dist در آن نیستند.
برای آپلود و ساخت روی GitHub، نصب Go روی ویندوز لازم نیست.
فرمان‌ها را مرحله‌به‌مرحله اجرا کن؛ اگر یک فرمان خطا داد، ادامه نده.

## نصب ابزارها

```powershell
winget install --id Git.Git --exact --source winget
winget install --id GitHub.cli --exact --source winget
```

PowerShell را ببند و دوباره باز کن، سپس:

```powershell
git --version
gh --version
```

اگر winget در دسترس نیست، Git را از https://git-scm.com/install/windows و GitHub CLI
را از https://cli.github.com نصب کن و PowerShell را دوباره باز کن.

## استخراج ZIP

فایل tunnel-lab-0.4.0-source.zip را در Downloads ذخیره کن.
هش SHA-256 اعلام‌شده در پیام دانلود را با Get-FileHash مقایسه کن.

```powershell
$archive = Join-Path $env:USERPROFILE 'Downloads/tunnel-lab-0.4.0-source.zip'
Get-FileHash -LiteralPath $archive -Algorithm SHA256
$destination = Join-Path $env:USERPROFILE 'Projects/TunnelLab-0.4-source'
if (Test-Path -LiteralPath $destination) { throw 'Destination exists; choose a new destination folder.' }
Expand-Archive -LiteralPath $archive -DestinationPath $destination
Set-Location (Join-Path $destination 'tunnel-lab')
Get-ChildItem -Force
```

go.mod و README.md باید در همین پوشه باشند. workflows هم همراه سورس وارد می‌شوند.
دستورهای Git را در همین پوشه اجرا کن، نه در Downloads یا پوشهٔ بالاتر.

## ورود به حساب GitHub

```powershell
gh auth login --hostname github.com --git-protocol https --web --scopes workflow
gh auth setup-git --hostname github.com
gh auth status
```

کد یک‌بارمصرفی را که gh نمایش می‌دهد در صفحهٔ رسمی ورود وارد کن و دسترسی را تأیید کن.
اگر gh برای اتصال Git به حساب پرسید، Yes را انتخاب کن. رمز/توکن را در فایل پروژه قرار نده.
مجوز workflow برای ارسال فایل‌های GitHub Actions درخواست شده است.

## ساخت مخزن جدید و آپلود کامل

نام مخزن نمونه است؛ قبل از اجرا در صورت تمایل تغییرش بده. این مسیر یک مخزن جدید می‌سازد.
اگر مخزن از قبل ساخته‌ای، به بخش بعد برو و gh repo create را اجرا نکن.

```powershell
$RepoName = 'tunnel-lab-test'
$GitHubUser = gh api user --jq .login
$GitHubId = gh api user --jq .id
git init -b main
git config --local user.name "$GitHubUser"
git config --local user.email "${GitHubId}+${GitHubUser}@users.noreply.github.com"
git config --local core.autocrlf false
git add .
git diff --cached --name-only
git commit -m "Prepare v0.4.0-alpha for deployment tests"
gh repo create "$RepoName" --private --source . --remote origin --push
gh repo view --web
```

مخزن Private ساخته می‌شود. سورس، README، تست‌ها، systemd و workflowها ارسال می‌شوند.
فایل‌های runtime مثل demo و کلیدهای خصوصی نباید جزو فهرست git diff باشند.
پوشهٔ استخراج‌شدهٔ این بسته خودش شامل کلید خصوصی نیست.

## اگر مخزن را قبلاً در سایت ساخته‌ای

مخزن مقصد برای این مسیر باید خالی باشد؛ بدون README یا commit اولیه.
بخش git init تا git commit را اجرا کن، سپس به‌جای gh repo create:

```powershell
$RepoUrl = 'https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git'
git remote add origin "$RepoUrl"
git push -u origin main
```

مقادیر URL را واقعی کن. اگر مخزن commit دارد یا remote از قبل ثبت شده، force push نکن؛
متن خطا را بررسی کن. دستورهای نمونه برای پروژهٔ تازه‌اند.

## بررسی تست‌های GitHub

```powershell
gh run list --workflow ci.yml
gh run watch --exit-status
```

اگر فهرست خالی بود، کمی بعد دوباره gh run list را اجرا کن.
در منوی gh run watch، جدیدترین اجرای Checks را انتخاب کن؛ باید موفق شود.
برای دیدن خطای آخرین اجرا در صورت شکست:

```powershell
gh run view --log-failed
```

## ساخت نسخهٔ انتشار

فقط بعد از موفق‌شدن Checks:

```powershell
git tag v0.4.0-alpha
git push origin v0.4.0-alpha
gh run list --workflow release.yml
gh run watch --exit-status
gh release view v0.4.0-alpha --web
```

در منوی watch اجرای Draft release را انتخاب کن. اگر هنوز ظاهر نشده بود، list را دوباره اجرا کن.
workflow دو بستهٔ Linux amd64 و arm64 و SHA256SUMS می‌سازد و Draft prerelease ایجاد می‌کند.
در صفحهٔ Releases پیش‌نویس را بررسی کن؛ برای انتشار، Publish release را خودت انتخاب کن.
مخزن Private با انتشار Release عمومی نمی‌شود؛ لینک دانلود خصوصی برای همه قابل‌دسترسی نیست.
دستور curl عمومیِ نصب را قبل از مشخص‌شدن وضعیت مخزن/انتشار استفاده نکن.

## ارسال تغییرهای بعدی

همیشه از همان پوشهٔ سورس:

```powershell
git status
git add .
git diff --cached --name-only
git commit -m "Describe the update"
git push
```

برای انتشار بعدی باید VERSION و نسخهٔ کد هماهنگ تغییر کنند و تگ جدید ساخته شود؛
تگ v0.4.0-alpha را برای هر تغییر دوباره نساز.
