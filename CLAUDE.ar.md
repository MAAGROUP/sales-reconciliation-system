# CLAUDE.md (النسخة العربية)

هذا الملف يقدّم إرشادات لـ Claude Code (claude.ai/code) عند العمل على الكود في هذا المستودع.

## ما هو هذا المشروع

تطبيق Django 5 (تطبيق واحد: `salesapp`، وإعدادات المشروع في `config/`) لمطابقة المبيعات اليومية لفروع المطاعم. المبالغ بالريال العماني (3 خانات عشرية)، والنقد بالدرهم الإماراتي يُحوَّل بسعر صرف محفوظ في كل تقرير. المنطقة الزمنية `Asia/Muscat`. الواجهة قوالب Django تُعرض من الخادم، بدون أي خطوة بناء لـ JavaScript. الاعتماديات فقط: Django و openpyxl (لتصدير ملفات Excel).

## الأوامر

```bash
venv\Scripts\activate                      # البيئة الافتراضية على Windows (مجلد venv/ مستثنى من git)
pip install -r requirements.txt
python manage.py migrate
python manage.py create_admin <username> <password>   # إنشاء أول حساب مدير
python manage.py runserver                 # http://127.0.0.1:8000/login/

python manage.py test salesapp                                          # كل الاختبارات
python manage.py test salesapp.tests.CalendarStageTests                  # فئة واحدة
python manage.py test salesapp.tests.CalendarStageTests.test_full_day_moves_through_every_stage  # اختبار واحد

python manage.py makemigrations salesapp   # بعد أي تعديل على النماذج
```

لا يوجد أي linter أو formatter مُعدّ في المشروع.

## الإعدادات

الملف `config/settings.py` يقرأ هذه الإعدادات من متغيرات البيئة، مع قيم افتراضية للتطوير: `SECRET_KEY`، و `DEBUG` (افتراضيًا `'True'`)، و `ALLOWED_HOSTS`، و `HTTPS_ENABLED`، و `DB_ENGINE`/`DB_NAME`/`DB_USER`/`DB_PASSWORD`/`DB_HOST`/`DB_PORT`. إذا لم يُضبط `DB_ENGINE` يُستخدم SQLite محليًا. بيئة الإنتاج تستخدم PostgreSQL عبر هذه المتغيرات، فلا تكتب إعدادات قاعدة البيانات مباشرة في الكود. `VARIANCE_THRESHOLD` (قيمته 5) هو مقدار الفرق الذي يُعتبر فرقًا يستحق التنبيه. الـ cache من نوع LocMem ويُستخدم لتحديد عدد محاولات تسجيل الدخول.

## البنية

معظم المنطق موجود في ملفين كبيرين: `salesapp/models.py` (حوالي 600 سطر) و `salesapp/views.py` (حوالي 3200 سطر، views على شكل دوال مع دوال مساعدة كثيرة تبدأ بـ `_`). الملف `salesapp/urls.py` يربط الروابط بها.

**الأدوار والصلاحيات.** قيمة `UserProfile.role` واحدة من: `waiter`، `collector`، `audit`، `manager`، `sales_manager` (الاثنان للعرض فقط)، `admin`، `it`. كل view محمي بـ `@role_required(...)` من `decorators.py`. الدوران `admin` و `it` (`is_full_access`) يمرّان دائمًا. الـ decorator أيضًا يرفض أي ملف مرفوع أكبر من 10 ميجابايت على مستوى النظام كله. الصفحة الرئيسية `/` (`entry_gate`) تحوّل غير الـ waiters إلى صفحة دورهم (`_redirect_for_role`). الـ waiters يسجلون الدخول من `/login/` بكود الفرع وكلمة المرور (`branch_login_view`)، والباقون من `/staff-login/`. كل waiter مقيّد بفرعه `profile.branch`.

**دورة حياة الوردية.** الـ `ShiftEntry` هو تقرير واحد يرسله الـ waiter لفرع/تاريخ/وردية (عدد فئات النقد، صفوف الفيزا، مصادر التوصيل، الخصومات، المرفقات). يمر بأربع مراحل (`ENTRY_STAGES` / `_entry_stage` في views.py):
1. `awaiting_sales`: التدقيق (Audit) يراجع أرقام المبيعات ويضبط `is_audited`.
2. `awaiting_collection`: المحصّل (collector) يعيد عدّ النقد وينشئ `CollectorHandover` (علاقة واحد لواحد، `entry.collector`).
3. `awaiting_cash_approval`: التدقيق يطابق فرق النقد (`handover.reconciled`؛ الملاحظة إلزامية إذا كان هناك فرق).
4. `complete`.

عندما تُعتمد كل الورديات `1..branch.shifts_per_day` ليوم ما، يغلق التدقيق اليوم بـ `DayClose`، الذي يحفظ رقم Foodics لـ**اليوم كاملًا**. فرق اليوم = مجموع `sales_actual` لورديات اليوم − رقم Foodics. بشكل منفصل، يمكن للـ waiter رفع طلب على تقرير (`request_status`: pending/approved/rejected). رفض الطلب يتطلب ملاحظة من التدقيق في `request_decision_note`.

**المجاميع تُحسب دائمًا على الخادم.** الدالتان `ShiftEntry.save()` و `CollectorHandover.save()` تستدعيان `recalculate()`. لا تثق أبدًا بالمجاميع المرسلة من المتصفح. حفظ `CollectorHandover` يعيد حفظ الـ `ShiftEntry` التابع له، لأنه بعد عدّ المحصّل يحل نقده محل نقد الـ waiter في `final_cash_total`. قيمة `cash_total` الأصلية للـ waiter تبقى محفوظة لحساب الفرق. مبلغ إلغاء النقد للمعلومية فقط ولا يُخصم. `sales_actual` (نقد + فيزا، بدون التوصيل) هو الرقم الذي يُقارن برقم Foodics. عند كتابة أي منطق جديد للمبالغ، استخدم `Decimal` والدالتين المساعدتين `_dec`/`_clean_number`.

**سجل التعديلات.** عند أول حفظ، يحتفظ النموذجان بـ `original_snapshot`. تصحيحات التدقيق تُقارن بهذه النسخة (`_shift_field_diffs`، `_compute_handover_changes`) وتُعرض بصيغة "تغيّر من X إلى Y". أي إجراء مهم يجب أن يستدعي `log_activity(request, action, description, details=...)`. قيمة `action` يجب أن تكون من `ActivityLog.ACTION_CHOICES`، وإضافة قيمة جديدة تتطلب migration.

**تاريخ العمل.** لكل فرع ساعات عمل (`day_cutoff` ← `day_end`)، وقد تمتد بعد منتصف الليل. الدالة `Branch.business_date()` تحدد التاريخ الذي ينتمي له التقرير. التقرير المرسل بعد الإغلاق يُحسب لليوم التالي ويُعلَّم بـ `submitted_late`. استخدم هذه الدالة بدلًا من `timezone.localdate()` كلما احتجت تاريخ تقرير فرع.

**كالندر الفرع (صفحة الأوديت).** فتح فرع في `/dashboard/` يجلب `branch_calendar_view` (`/dashboard/calendar/`)، والذي يرجّع جزء القالب `_calendar_body.html` فقط: شهر فيه عدد الشفتات في كل مرحلة لكل يوم عمل، وكاردات الاعتماد لليوم المختار. الكاردات ترسل للـ views الموجودة (`approve_all`، `close_day`، `cash_reconcile_action`، `collector_approve_all`) مع `next` يعيد فتح نفس الفرع واليوم (`?cal_branch=&cal_month=&cal_day=`). هذه الـ views تفضّل `_safe_next(request)` على رجوعها الافتراضي، فحافظ على هذا عند تعديلها. اليوم يُحسب Missing فقط من `Branch.start_date` (أو من أول تقرير للفرع إذا كان فارغًا). في الكالندر يبقى الشفت في Sales Review لين يتسكّر يومه (`_calendar_stage`)؛ وفي باقي النظام المرحلة تأتي من `_entry_stage`.

**وحدات أخرى:** `BankDeposit` (مع `BankDepositEvent`/`BankDepositFile`) هو الإيداع البنكي الدوري الذي يقوم به المحصّل ويغطي فترة من نقد الفروع، مع إمكانية استثناء فروع ومسار إرجاع/اعتماد. `WaiterResetLink` يوفّر روابط إعادة تعيين كلمة المرور للـ waiters عبر رمز (token). تقرير المبيعات اليومي متاح كصفحة HTML وكملف Excel (عبر openpyxl). الملفات المرفوعة تُحفظ في `media/` (مستثنى من git).

**القوالب.** موجودة في `salesapp/templates/salesapp/`. الملفات التي تبدأ بـ `_` أجزاء مشتركة تُضمَّن في عدة صفحات، مثل منتقي الفروع، وفلتر المراحل، وبطاقات النقد والملاحظات. الفلاتر المخصصة في `templatetags/app_filters.py`. نصوص الواجهة بالإنجليزية. حقول الأرقام تقبل الأرقام العربية/الهندية، والـ views تحوّلها إلى أرقام إنجليزية.
