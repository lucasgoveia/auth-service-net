﻿FROM mcr.microsoft.com/dotnet/aspnet:9.0-azurelinux3.0-distroless-composite AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["./Directory.Packages.props", "./"]
COPY ["./Directory.Build.props", "./"]
COPY ["src/AuthService.WebApi/AuthService.WebApi.csproj", "src/AuthService.WebApi/"]
COPY ["src/AuthService.Common/AuthService.Common.csproj", "src/AuthService.Common/"]
COPY ["src/AuthService.Consumers/AuthService.Consumers.csproj", "src/AuthService.Consumers/"]
COPY ["src/AuthService.EmailTemplating/AuthService.EmailTemplating.csproj", "src/AuthService.EmailTemplating/"]
COPY ["src/AuthService.Mailing/AuthService.Mailing.csproj", "src/AuthService.Mailing/"]
COPY ["src/AuthService.Messages/AuthService.Messages.csproj", "src/AuthService.Messages/"]
RUN dotnet restore "src/AuthService.WebApi/AuthService.WebApi.csproj"
COPY . .
WORKDIR "/src/src/AuthService.WebApi"
RUN dotnet build "AuthService.WebApi.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AuthService.WebApi.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthService.WebApi.dll"]
