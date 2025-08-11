namespace NewsApi.Endpoints;

using NewsApi.Domain.Abstractions;
using NewsApi.Domain.DTOs;
using NewsApi.Domain.Models;

public static class NewsEndpoints
{
    public static IEndpointRouteBuilder MapNewsEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/news").WithTags("News");

        // Anonim erişim GET herkese açık
        group.MapGet("", async (INewsRepository repo, int? limit, CancellationToken ct) =>
        {
            var items = await repo.GetLatestAsync(limit is > 0 and <= 200 ? limit.Value : 50, ct);
            var result = items.Select(n => new NewsDto(n.Id.ToString(), n.Title, n.Description, n.PublishedAt));
            return Results.Ok(result);
        }).AllowAnonymous();

        // Admin-only: parent grubun altında BOŞ prefix’li ALT GRUP
        var admin = group.MapGroup("")
                         .RequireAuthorization("AdminOnly");

        admin.MapPost("", async (INewsRepository repo, NewsDto dto, CancellationToken ct) =>
        {
            var doc = new News { Id = dto.Id, Title = dto.Title, Description = dto.Description, PublishedAt = dto.PublishedAt.ToUniversalTime() };
            await repo.CreateAsync(doc, ct);
            return Results.Created("/api/news", new NewsDto(doc.Id, doc.Title, doc.Description, doc.PublishedAt));
        });

        admin.MapPost("seed", async (INewsRepository repo, CancellationToken ct) =>
        {
            var now = DateTime.UtcNow;
            var docs = new[]
            {
                new News{ Title="Yeni Kuantum İşlemci Test Sonuçlarını Açıkladı", Description="Teknoloji firması, geliştirdiği yeni nesil kuantum işlemcisinin laboratuvar test sonuçlarını açıkladı. Cihaz, önceki modellere kıyasla %40 daha hızlı işlem kapasitesi ve %25 daha düşük enerji tüketimi sunuyor. Özellikle yapay zeka eğitimleri, bilimsel simülasyonlar ve karmaşık veri analizlerinde büyük performans artışı sağlayacağı öngörülüyor. Uzmanlar, bu gelişmenin endüstride yeni bir dönemi başlatabileceğini belirtiyor.", PublishedAt=now.AddDays(-1)},
                new News{ Title="Yapay Zeka ile Kod Üretiminde Büyük Sıçrama", Description="Araştırmacılar, yeni geliştirdikleri yapay zeka modelinin karmaşık yazılım projelerinin %60’ını insan müdahalesine gerek kalmadan tamamlayabildiğini duyurdu. Model, yalnızca kod üretmekle kalmıyor, aynı zamanda kodun optimizasyonunu ve hata kontrolünü de otomatik yapıyor. Bu sayede proje süreleri ciddi oranda kısalırken hata oranı da düşüyor. Teknolojinin, yazılım geliştirme süreçlerini kökten değiştireceği düşünülüyor.", PublishedAt=now.AddDays(-2)},
                new News{ Title="Veri Merkezi Enerji Tüketimini Yarıya İndiren Teknoloji", Description="Yeni nesil sıvı soğutma sistemi, veri merkezlerinde enerji tüketimini %50 oranında azaltmayı başardı. Sistem, mevcut altyapıya entegre edilebilecek şekilde tasarlandığı için kurulum süresi oldukça kısa. Enerji tasarrufunun yanı sıra, karbon salınımını da önemli ölçüde düşürüyor. Bu gelişme, sürdürülebilir bilişim çözümlerine doğru atılmış büyük bir adım olarak değerlendiriliyor.", PublishedAt=now.AddDays(-3)},
                new News{ Title="Siber Güvenlikte Yeni Şifreleme Standardı Kabul Edildi", Description="Uluslararası standart belirleyici kurumlar, kuantum bilgisayarların potansiyel tehditlerine karşı dayanıklı yeni bir şifreleme standardını onayladı. Standart, uzun vadeli veri saklama ve güvenli iletişim için yüksek koruma sağlıyor. Kriptografi uzmanları, bu teknolojinin finans, sağlık ve devlet kurumlarında hızla yaygınlaşacağını öngörüyor. Yeni sistemin, mevcut altyapılara entegre edilmesi için küresel bir geçiş planı hazırlandı.", PublishedAt=now.AddDays(-4)},
                new News{ Title="Bulut Depolamada Anlık Senkronizasyon Özelliği Duyuruldu", Description="Bir bulut hizmet sağlayıcısı, dosyaların cihazlar arasında anında senkronize edilmesini sağlayan yeni bir özelliğini tanıttı. Özellik, özellikle büyük dosyalar üzerinde bile gecikmesiz çalışmasıyla dikkat çekiyor. Kullanıcılar, bir cihazda yaptıkları değişiklikleri anında diğer cihazlarında görebilecek. Bu yenilik, uzaktan çalışma ve ekip işbirliği süreçlerinde ciddi verimlilik artışı sağlayacak.", PublishedAt=now.AddDays(-5)}
            };
            await repo.CreateManyAsync(docs, ct);
            return Results.Ok(new { inserted = docs.Length });
        });

        admin.MapPut("{id}", async (string id, NewsUpdateDto dto, INewsRepository repo, CancellationToken ct) =>
        {
            var ok = await repo.UpdateAsync(id, dto.Title, dto.Description, ct);
            return ok ? Results.Ok("Haber güncellendi.") : Results.NotFound("Haber bulunamadı.");
        });

        admin.MapDelete("", async (INewsRepository repo, CancellationToken ct) =>
        {
            var deleted = await repo.DeleteAllAsync(ct);
            return Results.Ok(new { deleted });
        });

        admin.MapDelete("{id}", async (string id, INewsRepository repo, CancellationToken ct) =>
        {
            var ok = await repo.DeleteAsync(id, ct);
            return ok ? Results.Ok("Haber silindi.") : Results.NotFound("Haber bulunamadı.");
        });

        return routes;
    }
}
