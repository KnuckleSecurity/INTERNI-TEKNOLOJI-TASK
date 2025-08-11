# INTERNIA TEKNOLOJI TASK

# TASK 1 -> interniaDiscover & interniaMap 

Bu kılavuz, **interniaDiscover.py** (canlı host keşfi) ve **interniaMap.py** (port tarama + servis/versiyon + opsiyonel CVE eşlemesi) araçlarının kurulumu ve kullanımını adım adım açıklar.

> **Önemli:** Her iki araç da **Nmap** komut satırı aracını kullanır. Nmap’in sisteminizde kurulu ve `PATH` üzerinde erişilebilir olduğundan emin olun.


---

## 1) Kurulum

### Gereksinimler
- **Python**: 3.8 veya üzeri
- **Nmap**: [https://nmap.org/download.html](https://nmap.org/download.html)
- **Python paketleri**: `colorama`, `requests`

### Kurulum Adımları
```bash
# 1) Sanal ortam (opsiyonel ama tavsiye edilir)
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# 2) Bağımlılıklar
pip install -r requirements.txt
```

> **Windows ipucu:** Nmap kurulumundan sonra Terminal’i kapatıp yeniden açın ki `nmap.exe` PATH’e eklensin.


---

## 2) interniaDiscover.py — Canlı Host Keşfi

**Amaç:** Ağda **canlı cihazları** tespit eder. Farklı ping yöntemlerini kullanır (ICMP, TCP SYN/ACK, UDP, ARP, IP Protocol).

### Temel Kullanım
```bash
python interniaDiscover.py 192.168.1.0/24
python interniaDiscover.py 192.168.1.65 --vv --packet-trace --live
python interniaDiscover.py targets.txt --methods PS,PA --json out.json
python interniaDiscover.py 203.0.113.0/24 --preset stealth
```

### Önemli Argümanlar
- **Hedef girdisi (`target`)**: CIDR (`192.168.1.0/24`), tek IP, aralık, *veya* `targets.txt` dosyası.
- **--methods**: `all` veya virgülle ayırarak: `PE,PP,PM,PS,PA,PU,PR,PO`
  - `PE`: ICMP Echo Ping (klasik ping)
  - `PP`: ICMP Timestamp
  - `PM`: ICMP Address Mask
  - `PS`: TCP SYN Ping (örn. `--ps-ports 22,80,443,3389`)
  - `PA`: TCP ACK Ping (örn. `--pa-ports 80,443`)
  - `PU`: UDP Ping (örn. `--pu-ports 53,123`)
  - `PR`: ARP Ping (aynı subnet’te çok güvenilir)
  - `PO`: IP Protocol Ping (örn. `--po-protos 1,6,17,47`)
- **--preset {fast|stealth|thorough}**
  - `fast`: `PE,PS,PR` + `-T3` + `--max-rate 200`
  - `stealth`: `PS,PA,PU` + `-T1` + `--scan-delay 200ms` + `--max-rate 30` + `--fragment`
  - `thorough`: `all` + `-T2` + `--scan-delay 100ms` + `--max-rate 80`
- **Görünürlük/Takip**: `--vv`, `--packet-trace`, `--live`, `--stats-every 2s`
- **Evasion/Timing**: `-T0…-T5`, `--scan-delay 200ms`, `--max-rate 50`, `--decoy <decoys>`, `--spoof-mac 0`, `--src-ip <IP>`, `--iface <iface>`, `--fragment`, `--mtu 8`, `--proxies`, `--defeat-rst-ratelimit`
- **Çıktı**: `--json out.json`, `--csv out.csv`
- **Diğer**: `--explain` (seçilen yöntemleri tarama öncesi açıklar), `--dry-run`, `--quiet`

### Örnek Senaryolar
- **LAN’da hızlı keşif (ARP + SYN)**:
  ```bash
  python interniaDiscover.py 192.168.1.0/24 --methods PR,PS --ps-ports 22,80,443
  ```
- **FW arkasında yaşıyor mu? (ACK ping)**:
  ```bash
  python interniaDiscover.py 10.10.0.0/16 --methods PA --pa-ports 443,8443 --vv
  ```
- **Sonuçları kaydetme**:
  ```bash
  python interniaDiscover.py targets.txt --methods all --json discover.json --csv discover.csv
  ```

### Çıktı Örneği (özet)
```
=== ÖZET ===
Toplam benzersiz canlı host: 5
10.0.0.5      -      methods=PA,PS,PR
10.0.0.10     web-1  methods=PE,PS
...
```

### ÖRNERK GÖRSEL
![INTERNIADISCOVER](https://raw.githubusercontent.com/KnuckleSecurity/INTERNI-TEKNOLOJI-TASK/refs/heads/main/miscs/Pasted%20image%2020250811085329.png?token=GHSAT0AAAAAADI7M24D6OQK4D3UKBW3DWNE2EZSDPQ)


---

## 3) interniaMap.py — Port Tarama & Servis/Versiyon & CVE

**Amaç:** Seçilen hedef(ler)de port taraması yapar; servis/versiyon tespiti (`-sV`) ve opsiyonel **NVD** tabanlı **CVE** araması yapabilir.

### Temel Kullanım
```bash
python interniaMap.py 192.168.1.65
python interniaMap.py 192.168.1.0/24 --udp
python interniaMap.py 192.168.1.65 -p 80,443,5173 --service-version
python interniaMap.py targets.txt --os --cve --json out.json
python interniaMap.py 192.168.1.65 --preset stealth
```

### Önemli Argümanlar
- **Hedef girdisi (`target`)**: tek IP/host, CIDR (`192.168.1.0/24`) veya `targets.txt`
- **Port kapsamı** (birini seçin):
  - `-p 80,443,5173` (veya `1-65535`)
  - `--top-ports 2000`
  - `--popular web|remote|iot|mixed` (gömülü setler)
- **Tarama Teknikleri**:
  - TCP: `--connect` (varsayılan), `--syn`, `--ack`, `--fin`, `--null`, `--xmas`, `--maimon`, `--window`
  - UDP: `--udp`
- **Derinlik**:
  - `-sV, --service-version` (servis/versiyon)
  - `--os` (OS tespiti)
  - `-A, --aggressive` (küme: OS + script + traceroute vb.)
- **Verbosity/Trace**: `--vv`, `--packet-trace`, `--live`, `--stats-every 2s`
- **Evasion/Timing**: `-T0…-T5`, `--scan-delay`, `--max-rate`, `--min-rate`, `--spoof-mac`, `--src-ip`, `--iface`, `--fragment`, `--mtu`, `--proxies`, `--defeat-rst-ratelimit`
- **Çıktı**: `--json out.json`, `--csv out.csv`
  - **CVE eşleme (NVD)**: `--cve` (opsiyonel), `--cve-max 5`

### CVE Eşleme Nasıl Çalışır?
- `--cve` kullanıldığında, **tüm açık portlar** için servis/bannerdan **ürün** ve **versiyon** bilgisi toplanır (ör. `nginx 1.18.0`).
- Bu metin ile **NVD** API’de arama yapılır ve ilk sonuçlardan kısa bir özet eklenir.
- **Öneri:** Doğruluk için **`-sV`** ile birlikte kullanın.

```bash
python interniaMap.py 192.168.1.65 -p 80,443 -sV --cve --cve-max 3 --json scan.json
```

### Presetler
- `fast`: `--top-ports 200` + `-T4` + `--max-rate 1000`
- `stealth`: `-T1` + `--scan-delay 200ms` + `--max-rate 50` + `--fragment` (SYN ile uyum notu: Connect taramada fragment etkisizdir)
- `thorough`: `-sV` + `--top-ports 2000` + `-T2` + `--scan-delay 100ms` + `--max-rate 200`

### Çıktı Örneği (özet)
```
=== SONUÇ ===
[+] 192.168.1.65 (hostname: -) — 2 açık port
    • tcp/80   http — nginx 1.18.0
        ↳ CVE-2021-23017: ...
    • tcp/443  https — nginx 1.18.0 (TLS1.2)
        ↳ CVE-2021-...: ...
```

### ÖRNEK GÖRSEL
  
![INTERNIAMAP](https://raw.githubusercontent.com/KnuckleSecurity/INTERNI-TEKNOLOJI-TASK/refs/heads/main/miscs/Pasted%20image%2020250811083558.png?token=GHSAT0AAAAAADI7M24CQMBXP635SIHFO6AI2EZSDFA)

---

## 4) İleri Seçenekler ve İpuçları

- **Hedef dosyası (targets.txt)**: Her satıra bir hedef yazın (IP, CIDR veya host adı).
- **DNS’i kapatma**: Araçlar varsayılan olarak `-n` ile DNS çözümlemeyi kapatır (daha hızlı ve gürültüsüz).
- **Windows PowerShell örneği**:
  ```powershell
  python .\interniaMap.py 192.168.1.65 --vv --stats-every 3s --json out.json
  python .\interniaDiscover.py 192.168.1.0/24 --methods PR,PS --ps-ports 22,3389 --csv out.csv
  ```
- **Hız / Gürültü dengesi**: `-T4/5` ve yüksek `--max-rate` hızlıdır ama tespit edilme ve paket kaybı riski artar.
- **UDP taramaları**: `--udp` + yeterli izinler/gereken firewall ayarları. UDP’de false negative olasılığı daha yüksektir.
- **Deadlock önleme**: Her iki araçta da Nmap’ın `stdout`/`stderr` birleşik okunur; `--live` ile anlık log akışı alabilirsiniz.


---

## 5) Hata Giderme (Troubleshooting)

- **`Nmap bulunamadı` hatası**: Nmap kurulu değil ya da PATH’te değil.
- **`Permission denied` / Raw socket gereken işlemler**: Bazı teknikler yönetici/Root gerektirebilir. Windows’ta “Yönetici olarak çalıştır”, Linux’ta `sudo` kullanın.
- **`--cve` sonuç getirmiyor**: Banner boş olabilir; doğruluk için `-sV` ekleyin. NVD oran limiti/ping’e takılmamak için bir süre sonra tekrar deneyin.
- **`--packet-trace` çok gürültülü**: Sadece hata ayıklamada kullanın.
- **Çok yavaş**: `--top-ports` sayısını düşürün veya preset `fast` deneyin. `--max-rate` ile hız artırın (kayba dikkat).


---

## 6) Hukuki Uyarı

Bu araçları yalnızca **yetkili olduğunuz** sistem ve ağlarda kullanın. İzinsiz tarama **yasa dışıdır** ve sorumluluk size aittir.


---

## 7) Sürüm Bilgisi

- Kılavuz: 2025-08-11
- Scriptler: `interniaDiscover.py` ve `interniaMap.py` (kullanım örnekleri ve argüman isimleri bu sürüme göredir)





# TASK 2 -> Internia Teknoloji — News Platform Kılavuz (API + Frontend) 

Bu doküman **Internia Teknoloji** için geliştirilen Haber Platformu’nun iki ana bileşenini açıklamak adına hazırlanmıştır.

1) **API (Backend)** — Nasıl çalışır, mimari, güvenlik, konfigürasyon ve endpoint'ler. 
2) **Frontend (React / Vite)** — Uygulama akışı, oturum yönetimi, kullanılan endpoint’ler ve entegrasyon notları

---

## 1) ⚙️BACKEND APIs

### 1.1 Amaç ve Genel Bakış
**News API**, haber içeriklerinin güvenli şekilde yayınlanması için geliştirilmiş bir **.NET 8 Minimal API** uygulamasıdır. Veriler **MongoDB**’de tutulur. Kimlik doğrulama **JWT** ile yapılır; token’lar **HttpOnly Cookie** olarak set edilir. Yönetim (create/update/delete) işlemleri yalnızca **Admin** rolündeki kullanıcıyla yapılır; **okuma** (GET) herkese açıktır.

### 1.2 Mimarinin Kısa Özeti
```
Client (Browser/Frontend)
  └─(fetch + credentials: 'include')→  News API (.NET 8)
       ├─ AuthEndpoints  → Login/Logout (JWT üretimi, HttpOnly cookie)
       └─ NewsEndpoints  → Haber CRUD + Seed
                             └─ Mongo Repository → MongoDB
```
- **Program.cs**: CORS, Authentication/Authorization, Swagger, endpoint grupları
- **AuthEndpoints.cs**: `/auth/login`, `/auth/logout` (JWT üretim/silme)
- **NewsEndpoints.cs**: `/api/news` CRUD ve `/api/news/seed`
- **JWT Doğrulama**: Cookie’deki token middleware tarafından doğrulanır

### 1.3 🔐Güvenlik Modeli
- **HttpOnly Cookie**: Token JS ile okunamaz → XSS riskini azaltır.
- **CORS + Credentials**: Frontend domain’i izinli origin olarak tanımlanır; istekler `credentials: 'include'` ile yapılır.
- **HTTPS (Prod)**: Cookie `Secure=true` ile set edilir; `SameSite` senaryoya uygun yapılandırılır.
- **Rol Bazlı Yetki**: Admin gereken uçlar `[Authorize(Roles=\"Admin\")]` ile korunur.

### 1.4 🛠️ Konfigürasyon
`appsettings.json` (örnek):
```json
{
  "Mongo": {
    "ConnectionString": "mongodb://localhost:27017", -> MONGO ATLAS BAĞLANTISI
    "Database": "newsdb"
  },
  "Jwt": {
    "Issuer": "news-api",
    "Audience": "news-app",
    "Key": "jwt key", -> JWT SECRET ANAHTAR
    "ExpiresMinutes": 60
  }
}
```
### 1.5 🌐Uç Noktalar (Endpoint’ler)

| Metod | Yol                 | Açıklama                         | Yetki     |
|------:|---------------------|----------------------------------|-----------|
| GET   | `/api/news?limit=`  | Haberleri listele (varsayılan 50)| Public    |
| POST  | `/api/news`         | Haber oluştur                    | Admin     |
| PUT   | `/api/news/{id}`    | Haber güncelle                   | Admin     |
| DELETE| `/api/news/{id}`    | Haberi sil                       | Admin     |
| DELETE| `/api/news`         | Tüm haberleri sil                | Admin     |
| POST  | `/api/news/seed`    | Örnek veri ekle                  | Admin     |
| POST  | `/auth/login`       | Giriş yap → cookie set edilir    | Public    |
| POST  | `/auth/logout`      | Çıkış yap → cookie temizlenir    | Public    |

Örnek `POST /api/news` gövdesi:
```json
{
  "title": "Başlık",
  "description": "Açıklama",
  "publishedAt": "2025-08-11T09:00:00Z"
}
```

### 1.6 Örnek Etkileşim Senaryosu (cURL)
```bash
# 1) Login olup cookie yakala
curl -c cookies.txt -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"12345"}'

# 2) Admin endpointlere cookie ile eriş
curl -b cookies.txt -X POST http://localhost:5000/api/news/seed
curl -b cookies.txt -X POST http://localhost:5000/api/news \
  -H "Content-Type: application/json" \
  -d '{"title":"Deneme","description":"Açıklama","publishedAt":"2025-08-11T09:00:00Z"}'

# 3) Public listeleme (cookie gerekmez)
curl http://localhost:5000/api/news?limit=5

# 4) Çıkış
curl -b cookies.txt -X POST http://localhost:5000/auth/logout
```


---

## 2) 📚Frontend (React / Vite)

**Frontend**, **React** ve **Vite** teknolojileri kullanılarak geliştirilmiş olup, tamamen **Single Page Application (SPA)** mimarisi ile yapılandırılmıştır. Bu sayede uygulama, istemci tarafında tek bir HTML sayfası üzerinde çalışarak, sayfa yenilemesine gerek kalmadan dinamik içerik güncellemeleri yapar ve kullanıcı deneyimini kesintisiz hale getirir.

### 2.1 Router’sız Etkileşim
Uygulama internal bir `route` state’i ile sayfaları değiştirir: `home`, `login`, `news`, `panel`.

- **Nav**: Panel sekmesi yalnızca **`isAuthed`** iken görünür.
- **Home**: Son 3 haberi çeker (`/api/news?limit=3`), banner ve kısayollar gösterir.
- **NewsPublic**: Public haber listesi (`/api/news`), giriş gerekmez.
- **Login**: `/auth/login` başarılı olursa UI’da `isAuthed=true` yapılır (cookie JS’te okunmaz, oturum sinyali UI state’tir).
- **Panel**: Admin işlemleri (seed, ekle, güncelle, sil). 401 alınırsa UI **logout** görünümü verilir.

### 2.4 Oturum Akışı (Login/Logout)
- **Login** (Form → `/auth/login`): 200 gelirse cookie tarayıcıya set edilir → UI `isAuthed=true` → kullanıcı **Panel**’e yönlendirilir.
- **Admin İşlemi**: Panel içindeki çağrılar (POST/PUT/DELETE) cookie ile otomatik yetkilendirilir. 401 yakalanırsa `onUnauthorized()` tetiklenir (UI logout’a döner).
- **Logout** (`/auth/logout`): Cookie temizlenir, UI `isAuthed=false`, Panel görünmez.

### 2.5 Panel İşlevleri ve Backend Eşleşmesi
- **Liste**: `GET /api/news`
- **Ekle**: `POST /api/news` — body: `{ title, description, publishedAt }`
- **Güncelle**: `PUT /api/news/{id}` — body: `{ title, description }`
- **Sil (tek)**: `DELETE /api/news/{id}`
- **Sil (tümü)**: `DELETE /api/news`
- **Seed**: `POST /api/news/seed`

### 2.6 UI Davranışları
- **Panel Sekmesi**: Sadece `isAuthed=true` iken gösterilir.
- **401 Yönetimi**: `Error.message` `401` ile başlıyorsa toast + login’e yönlendirme.
- **Toast**: Kısa süreli bilgilendirme bileşeni (`useToast`).

### 2.7 Frontend Geliştirme / Çalıştırma
```bash
# Bağımlılıkları kur
npm i

# Geliştirme sunucusu 7777. Portta koşuyor
npm run dev

# Üretim derlemesi
npm run build
npm run preview
```

---
