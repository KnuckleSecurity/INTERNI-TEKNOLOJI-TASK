# NewsApi (MongoDB + Minimal API, .NET 8)

## Çalıştırma
```bash
dotnet restore
dotnet run
```

## Endpoint'ler
- `GET /api/news?limit=5` — Son haberleri getirir
- `POST /api/news` — Tek haber ekler (NewsDto)
- `POST /api/news/seed` — 5 adet mock haber ekler
- `PUT /api/news/{id}` — Title & Description günceller (NewsUpdateDto)
- `DELETE /api/news/{id}` — Tek haber siler
- `DELETE /api/news` — Tüm haberleri siler

## Yapı
- **Domain**: Modeller, DTO'lar, Abstraction
- **Infrastructure**: Mongo implementasyonu, Options, DI Extension
- **Endpoints**: Minimal API rotaları
- **Program.cs**: Bootstrap
