# Этап 1: Сборка
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Копируем файл проекта и восстанавливаем зависимости
# Предполагается, что Dockerfile лежит в корне решения
COPY ["AuthServer.Host/AuthServer.Host.csproj", "AuthServer.Host/"]
RUN dotnet restore "AuthServer.Host/AuthServer.Host.csproj" --disable-parallel

# Копируем весь остальной код и собираем
COPY . .
WORKDIR "/src/AuthServer.Host"
RUN dotnet build "AuthServer.Host.csproj" -c Release -o /app/build

# Этап 2: Публикация
FROM build AS publish
RUN dotnet publish "AuthServer.Host.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Этап 3: Финальный образ
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
EXPOSE 8080

# Устанавливаем часовой пояс (опционально, полезно для логов)
ENV TZ=Europe/Minsk

COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthServer.Host.dll"]