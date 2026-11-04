# تفسیر وضعیت در 0.4.3-alpha

این نسخه تغییر wire protocol ندارد و با پروفایل encrypted-preface/omit_sni نسخهٔ کارکرده سازگار است. هدف نخست دیدن مرحلهٔ اشباع و علت پایان اتصال در Direct TCP است، نه افزایش خودکار سقف یا سرعت.

## JSON وضعیت

فیلدهای موجود باقی می‌مانند و max_connections و idle_seconds از تنظیم فعال به پاسخ اضافه می‌شوند. در mode=edge/relay، شیء connection_diagnostics افزوده می‌شود:

| فیلد | معنی |
|---|---|
| setup_active | اتصال‌هایی که TCP/TLS/protocol/target آن‌ها آماده می‌شود |
| forwarding_active | اتصال‌هایی که وارد bridge شده‌اند؛ لزوماً همین لحظه بایت منتقل نمی‌کنند |
| probe_active | probeهای سمت سرور در حال اجرا |
| half_closed_active | زیرمجموعهٔ forwarding؛ یک جهت به EOF رسیده و جهت دیگر هنوز تمام نشده |
| peak_active | بیشترین active از شروع همین پردازش |
| setup_failures | شکست آماده‌سازی؛ تفکیک در setup_failure_counts |
| setup_failure_counts | تعداد شکست tcp_connect، tls_handshake، protocol_negotiation و target_connect |
| probe_failures | شکست درخواست probe پس از انتخاب پروتکل |
| idle_timeouts | پایان bridge بر اثر deadline بیکاری؛ دیگر در errorsِ Direct شمرده نمی‌شود |
| peer_disconnects | reset یا broken pipe؛ در errors نیز هست |
| transfer_failures | سایر خطاهای انتقال؛ در errors نیز هست |
| shutdown_closed | bridgeهایی که با لغو context پردازش بسته شده‌اند |
| last_error | زمان UTC، مرحله و نوع آخرین خطا؛ ممکن است null باشد |
| recent_events | حداکثر۸ رویداد آخر شامل خطا، idle و رد ظرفیت |

گرفتن snapshot از اتمیک‌های همزمان یک تراکنش واحد نیست؛ جمع gauges در یک لحظهٔ گذار ممکن است اندکی اختلاف داشته باشد. half_closed_active را دوباره به forwarding_active اضافه نکن. accepted شامل rejected است و تعداد موفق‌ها نیست. Probeها نیز در completedِ bridge شمرده نمی‌شوند.

همهٔ شمارنده‌ها process-local هستند و با restart صفر می‌شوند. نمودار یا ذخیرهٔ تاریخچهٔ دائمی هنوز اضافه نشده است. نبود خطای جدید، سلامت Xray یا مقصد کاربر را به‌تنهایی ثابت نمی‌کند. control_connected برای Direct کاربرد ندارد.

این diagnostics در Reverse و UDP-over-TLS هنوز instrument نشده است و در JSON آن حالت‌ها غایب است. نسخهٔ0.4.1 خارج اگر ارتقا نیافته باشد این فیلدها را ندارد؛ نبود فیلد را صفر خطا تفسیر نکن.

## به‌روزرسانی جفت موجود پس از تصمیم به نصب

فایل اجرایی جدید باید با checksum بررسی و selftest شود. installer اصلی instanceها را خودکار restart نمی‌کند. پروفایل و گواهی‌های کارکرده حفظ شوند. هر restart اتصال‌های فعال همان instance را قطع و شمارنده‌های آن را صفر می‌کند؛ ابتدا status و logهای مورد نیاز را ثبت کن.

نمونهٔ سرورهای فعلی:

- ایران: tunnellab@iran-direct.service و admin روی127.0.0.1:9084.
- خارج: tunnellab@outside-direct.service و admin روی127.0.0.1:9083.

نسخهٔ نصب‌شده را از tunnellab version و نسخهٔ پردازش اجراشده را از status مقایسه کن. نصب باینری جدید به‌تنهایی پردازش قدیمی را عوض نمی‌کند. برای گرفتن gauges هر دو سمت، ارتقای هر دو پردازش لازم است؛ ارتباط با نسخهٔ قدیمی نیز از نظر wire باید برقرار بماند.

افزایش max_connections یا کاهش idle_seconds بخشی از این نسخه نیست. قبل از تغییر آن‌ها بررسی کن setup_active، forwarding_active و half_closed_active هنگام بالا رفتن rejected چه مقداری دارند و CPU/RAM/FD چه وضعی دارند.
