FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["LoginPanel/LoginPanel.csproj", "LoginPanel/"]
RUN dotnet restore "LoginPanel/LoginPanel.csproj"
COPY . .
WORKDIR "/src/LoginPanel"
RUN dotnet build "LoginPanel.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "LoginPanel.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "LoginPanel.dll"]
