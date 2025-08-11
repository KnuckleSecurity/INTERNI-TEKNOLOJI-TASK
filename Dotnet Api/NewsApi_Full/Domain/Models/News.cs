namespace NewsApi.Domain.Models;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class News
{
    [BsonId, BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("title")]
    public string Title { get; set; } = string.Empty;

    [BsonElement("description")]
    public string Description { get; set; } = string.Empty;

    [BsonElement("publishedAt")]
    public DateTime PublishedAt { get; set; }
}
