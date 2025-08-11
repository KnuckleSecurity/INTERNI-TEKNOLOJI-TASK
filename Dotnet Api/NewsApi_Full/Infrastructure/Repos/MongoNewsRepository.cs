namespace NewsApi.Infrastructure.Repos;

using Microsoft.Extensions.Options;
using MongoDB.Driver;
using NewsApi.Domain.Abstractions;
using NewsApi.Domain.Models;
using NewsApi.Infrastructure.Options;

public sealed class MongoNewsRepository : INewsRepository
{
    private readonly IMongoCollection<News> _col;

    public MongoNewsRepository(IOptions<MongoOptions> opt)
    {
        var cfg = opt.Value;
        var client = new MongoClient(cfg.ConnectionString);
        var db = client.GetDatabase(cfg.Database);
        _col = db.GetCollection<News>(cfg.Collection);

        // Indexler (idempotent)
        var models = new[]
        {
            new CreateIndexModel<News>(Builders<News>.IndexKeys.Descending(x => x.PublishedAt)),
            new CreateIndexModel<News>(Builders<News>.IndexKeys.Text(x => x.Title).Text(x => x.Description))
        };
        _col.Indexes.CreateMany(models);
    }

    public async Task<IReadOnlyList<News>> GetLatestAsync(int limit = 50, CancellationToken ct = default) =>
        await _col.Find(FilterDefinition<News>.Empty)
                  .SortByDescending(x => x.PublishedAt)
                  .Limit(limit)
                  .ToListAsync(ct);

    public Task CreateAsync(News item, CancellationToken ct = default) =>
        _col.InsertOneAsync(item, cancellationToken: ct);

    public Task CreateManyAsync(IEnumerable<News> items, CancellationToken ct = default) =>
        _col.InsertManyAsync(items, cancellationToken: ct);

    public async Task<bool> UpdateAsync(string id, string title, string description, CancellationToken ct = default)
    {
        var filter = Builders<News>.Filter.Eq(x => x.Id, id);
        var update = Builders<News>.Update
            .Set(x => x.Title, title)
            .Set(x => x.Description, description);
        var result = await _col.UpdateOneAsync(filter, update, cancellationToken: ct);
        return result.ModifiedCount > 0;
    }

    public async Task<long> DeleteAllAsync(CancellationToken ct = default)
    {
        var result = await _col.DeleteManyAsync(FilterDefinition<News>.Empty, ct);
        return result.DeletedCount;
    }

    public async Task<bool> DeleteAsync(string id, CancellationToken ct = default)
    {
        var filter = Builders<News>.Filter.Eq(x => x.Id, id);
        var result = await _col.DeleteOneAsync(filter, ct);
        return result.DeletedCount > 0;
    }
}
