# interniaDiscover & interniaMap

Bu iki araç, Internia Teknoloji adına, ağ keşfi ve port tarama işlemlerini kolaylaştırmak için hazırlanmıştır.

- `interniaDiscover.py` → Canlı host keşfi (ping sweep, ARP, TCP SYN vb. yöntemler)
- `interniaMap.py` → Port tarama, servis/versiyon tespiti, opsiyonel CVE araması

## Gereksinimler

- Python 3.8+
- Nmap (PATH üzerinde erişilebilir olmalı)  
  [Nmap İndir](https://nmap.org/download.html)
- Python bağımlılıkları:
  ```bash
  pip install -r requirements.txt
