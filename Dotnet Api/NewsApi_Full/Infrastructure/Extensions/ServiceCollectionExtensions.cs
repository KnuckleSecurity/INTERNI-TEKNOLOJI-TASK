namespace NewsApi.Infrastructure.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NewsApi.Domain.Abstractions;
using NewsApi.Infrastructure.Options;
using NewsApi.Infrastructure.Repos;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMongoInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.Configure<MongoOptions>(config.GetSection(MongoOptions.SectionName));
        services.AddSingleton<INewsRepository, MongoNewsRepository>();
        return services;
    }
}
