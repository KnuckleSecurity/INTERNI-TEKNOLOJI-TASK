namespace NewsApi.Infrastructure.Options;

public sealed class MongoOptions
{
    public const string SectionName = "Mongo";
    public string ConnectionString { get; init; } = default!;
    public string Database { get; init; } = default!;
    public string Collection { get; init; } = default!;
}
