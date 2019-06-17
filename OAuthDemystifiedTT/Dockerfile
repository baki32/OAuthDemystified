FROM mcr.microsoft.com/dotnet/core/aspnet:3.0.0-preview6 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-preview6 AS build
WORKDIR /src
COPY ["/OAuthDemystifiedTT/OAuthDemystifiedTT.csproj", "OAuthDemystifiedTT/"]
COPY ["/OauthHandler/OauthHandler.csproj", "OauthHandler/"]
RUN dotnet restore "./OAuthDemystifiedTT/OAuthDemystifiedTT.csproj"
COPY . .
WORKDIR "/src/OAuthDemystifiedTT"
RUN dotnet build "OAuthDemystifiedTT.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "OAuthDemystifiedTT.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "OAuthDemystifiedTT.dll"]