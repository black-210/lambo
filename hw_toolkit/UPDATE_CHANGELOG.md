# تحديثات وتطويرات منصة أمن العتاد — `hw_toolkit v0.2.0`

> ملف التوثيق الشامل للتحديثات الجديدة في البنية البرمجية، الخوارزميات الفيزيائية والكهرومغناطيسية والنووية، وحدات الـ Assembly منخفضة المستوى، وقاعدة الثغرات.

---

## 1. ملخص التحديثات الجديدة

| المكوّن | المسار | ما تم إضافته / تطويره |
|---------|--------|------------------------|
| **محرك الكهرومغناطيسية والنووية العتادية** *(جديد)* | [em_nuclear.rs](file:///C:/Users/asus/Downloads/lambo/hw_toolkit/src/em_nuclear.rs) | معادلات ماكسويل للعمق الجلدي، فعالية قفص فاراداي، نبضة HEMP E1 المزدوجة الأسية، نموذج تسرب TEMPEST، ونماذج الإشعاع النووي (Weibull SEU/SEL، FIT، $Q_{crit}$، TID). |
| **محرك الـ ASM متعدد المعماريات** *(مُرقّى)* | [asm_payload.rs](file:///C:/Users/asus/Downloads/lambo/hw_toolkit/src/asm_payload.rs) | تعليمات `core::arch::asm!` حقيقية لمعماريتي `x86_64` و `aarch64` (ARM64): استعلام `cpuid` المباشر، قياس التوقيت التسلسلي `mfence; lfence; rdtscp`، هجوم توقيت الكاش `clflush` (Flush+Reload)، ومعايرة نوافذ الجليتش، بالإضافة إلى ARM64 `cntvct_el0` و `dc civac`. |
| **التحليل الفيزيائي والقنوات الجانبية** | [physical_analysis.rs](file:///C:/Users/asus/Downloads/lambo/hw_toolkit/src/physical_analysis.rs) | MAD، CUSUM، Z-score، Welch TVLA، NICV، SNR، هجوم CPA الكامل على AES S-Box (256 مفتاح)، Template Attack، طاقة CMOS ($E = \frac{1}{2}CV^2$)، والجهد المستحث بـ EMP ($V = -M \frac{dI}{dt}$). |
| **تحليل RF المتقدم** | [rf_scan.rs](file:///C:/Users/asus/Downloads/lambo/hw_toolkit/src/rf_scan.rs) | طيف FFT، Spectrogram (Hann)، قدرة dBm، مزيل تضمين AM/FM/PM، عدم توازن IQ، خطأ التردد CFO، نموذج Friis، ميزانية الرابط، المقطع الراداري RCS، وكشف التشويش وإعادة البث. |
| **قاعدة بيانات الثغرات** *(مُحدّثة)* | [vuln_db.rs](file:///C:/Users/asus/Downloads/lambo/hw_toolkit/src/vuln_db.rs) | إضافة ثغرات `HW-EMP-001` (HEMP E1)، `HW-RAD-001` (SEU/SEL)، و `HW-RF-004` (TEMPEST/Van Eck)، مع إصلاح توافق `serde` ومرشّحات البحث. |
| **نقطة الدخول والـ CLI** *(مُصلحة)* | [main.rs](file:///C:/Users/asus/Downloads/lambo/hw_toolkit/src/main.rs) | فصل الـ binary عن `lib.rs` لإصلاح أخطاء الربط، وإضافة الأمر الجديد `em-nuclear` وتوسيع `cpu` لعرض نتائج `CPUID` ومعايرة الكاش بالـ ASM. |

---

## 2. المعادلات الفيزيائية والهندسية المطبّقة

### أ) الكهرومغناطيسية ودرع فاراداي (`em_nuclear.rs`)
1. **العمق الجلدي (Skin Depth):**
   $$\delta = \sqrt{\frac{2}{\omega \mu \sigma}}$$
2. **فعالية الحجب الكلي لقفص فاراداي (Shielding Effectiveness):**
   $$SE_{\text{dB}} = A_{\text{dB}} + R_{\text{dB}} + B_{\text{dB}}$$
3. **نبضة HEMP E1 القياسية (IEC 61000-2-9):**
   $$E(t) = E_0 \cdot k \cdot \left(e^{-\alpha t} - e^{-\beta t}\right)$$
4. **الجهد المستحث على مسارات الـ PCB:**
   $$V_{\text{ind}} \approx E_{\text{eff}} \cdot L_{\text{trace}} + A_{\text{loop}} \cdot \mu_0 \cdot \frac{dH}{dt}$$
5. **نسبة الإشارة إلى الضوضاء في التنصت الكهرومغناطيسي (TEMPEST SNR):**
   حساب القدرة المستقبلة عبر الفتحة الفعّالة للهوائي ($A_e \approx 0.13 \lambda^2$) مقارنةً بأرضية الضوضاء الحرارية ($-174\text{ dBm/Hz} + 10\log_{10}(BW) + NF$).

### ب) التأثيرات النووية والإشعاعية على العتاد (`em_nuclear.rs`)
1. **المقطع العرضي للأحداث الفردية (Weibull SEU/SEL Cross-Section):**
   $$\sigma(L) = \sigma_{\text{sat}} \left[1 - \exp\left(-\left(\frac{L - L_{\text{th}}}{W}\right)^s\right)\right]$$
2. **معدل الأخطاء اللينة (Soft Error Rate in FIT):**
   $$\text{SER}_{\text{FIT}} = \Phi \cdot \sigma \cdot N_{\text{bits}} \cdot 3600 \cdot 10^9$$
3. **الشحنة الحرجة للانقلاب المنطقي (Critical Charge $Q_{\text{crit}}$):**
   $$Q_{\text{crit}} \approx \frac{1}{2} C_{\text{node}} V_{\text{dd}}, \qquad Q_{\text{dep}} \approx 10.35 \cdot \text{LET} \cdot t_{\text{Si}}$$
4. **إزاحة جهد العتبة بالجرعة المؤينة الكلية (TID $\Delta V_{\text{th}}$):**
   $$\Delta V_{\text{th}} \approx -k_{\text{tid}} \cdot D_{\text{rad}}^{\alpha}$$

### ج) فيزياء النانو والميكرو والتحكم الكهربائي (`em_nuclear.rs` + `asm_payload.rs`)
1. **سعة بوابة CMOS بمقياس النانومتر ($L_{gate}, W_{gate}, t_{ox}$ بـ nm):**
   $$C_g = \varepsilon_0 \varepsilon_r \frac{W_{\text{nm}} \cdot L_{\text{nm}}}{t_{\text{ox,nm}}}$$
2. **معادلة بلاك للهجرة الكهربائية في مسارات الطاقة (Electromigration MTTF):**
   $$\text{MTTF} = A \cdot J^{-n} \cdot \exp\left(\frac{E_a}{k_B T}\right)$$
3. **كثافة إشعاع الليزر المركّز لحقن الأعطال بالميكرومتر (LFI Spot Irradiance):**
   $$I_{\text{peak}} = \frac{E_{\text{pulse}} / \tau_{\text{pulse}}}{\pi (d_{\text{spot},\mu\text{m}} / 2)^2}$$
4. **استجابة دائرة RLC لخطوط الطاقة عند حقن نبضة Crowbar بالنانوثانية:**
   $$V(t) = V_{\text{dd}} - \Delta V \cdot e^{-\alpha t} \cos(\omega_d t)$$
5. **مُجدول نبضات الـ ASM بالنانوثانية ومولّد الشيفرة الآلية (`generate_asm_test_stub`):**
   - تحويل عرض النبضة بالنانوثانية إلى دورات ساعة دقيقة (`build_nanosecond_glitch_sequence`).
   - تنفيذ نبضة الـ Crowbar عبر منفذ التحكم الكهربائي (`asm_power_rail_crowbar_pulse` مع `--features asm`).
   - توليد مقاطع بايتات ASM تشخيصية لمعماريات `X86_64` و `Aarch64` و `ArmThumb2CortexM`.

---

## 3. وحدات الـ Assembly منخفضة المستوى (`asm_payload.rs`)

- **`asm_cpuid_security_caps()` (`x86_64`)**: استدعاء `cpuid` مباشر مع حفظ `rbx` لاستخراج علامات الأمان العتادية (`AES-NI`, `RDRAND`, `SGX`, `SMEP`, `SMAP`, `AVX/AVX2`, `Hypervisor`).
- **`asm_rdtscp_serialized()` (`x86_64`)**: حواجز تسلسل `mfence; lfence; rdtscp; lfence` لقياس الزمن بدقة دورة الساعة.
- **`asm_flush_and_probe_cycles()` (`x86_64`)**: تفريغ سطر الكاش بـ `clflush` ثم قياس زمن الوصول لكشف الفارق بين Hit و Miss في هجمات القنوات الجانبية.
- **`asm_arm64_cntvct()` و `asm_arm64_flush_and_probe()` (`aarch64`)**: نفس آليات القياس والتفريغ (`dc civac`, `dsb sy`, `isb`, `cntvct_el0`) لمعالجات الهواتف ARM64.
- **`inject_uart_io_port()` (`#[cfg(feature = "asm")]`)**: إرسال بايلود UART عبر منافذ الإدخال/الإخراج `out dx, al` بتوقيت مضبوط بالدورات.

---

## 4. أوامر التشغيل الجديدة

```powershell
cd C:\Users\asus\Downloads\lambo\hw_toolkit

# تشغيل جميع الاختبارات
cargo test

# فحص بصمة المعالج + قدرات CPUID ومعايرة الكاش بالـ ASM
cargo run -- cpu

# تدقيق الفيزياء الكهرومغناطيسية (Faraday/HEMP/TEMPEST) والنووية (SEU/LET)
cargo run -- em-nuclear --freq-hz 1000000000 --shield-m 0.001 --let-mev 15.0

# مسح RF وتشغيل خطة الاختبار الشاملة
cargo run -- rf-scan --center 433920000
cargo run -- demo --target stm32f411
```
