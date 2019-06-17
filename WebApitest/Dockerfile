FROM mcr.microsoft.com/dotnet/core/aspnet:3.0.0-preview6 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-preview6 AS build
WORKDIR /src
COPY ["/WebApitest/WebApitest.csproj", "WebApitest/"]
RUN dotnet restore "./WebApitest/WebApitest.csproj"
COPY . .
WORKDIR "/src/WebApitest"
RUN dotnet build "WebApitest.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "WebApitest.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "WebApitest.dll"]