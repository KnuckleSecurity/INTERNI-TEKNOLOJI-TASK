namespace NewsApi.Domain.Abstractions;

using NewsApi.Domain.Models;

public interface INewsRepository
{
    Task<IReadOnlyList<News>> GetLatestAsync(int limit = 50, CancellationToken ct = default);
    Task CreateAsync(News item, CancellationToken ct = default);
    Task CreateManyAsync(IEnumerable<News> items, CancellationToken ct = default);
    Task<bool> UpdateAsync(string id, string title, string description, CancellationToken ct = default);
    Task<long> DeleteAllAsync(CancellationToken ct = default);
    Task<bool> DeleteAsync(string id, CancellationToken ct = default);
}
