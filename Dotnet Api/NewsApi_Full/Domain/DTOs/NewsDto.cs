namespace NewsApi.Domain.DTOs;

public record NewsDto(string Id, string Title, string Description, DateTime PublishedAt);
