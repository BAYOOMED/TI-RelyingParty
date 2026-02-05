FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY ["RelyingParty/RelyingParty.csproj", "RelyingParty/"]
RUN dotnet restore "RelyingParty/RelyingParty.csproj" -a $TARGETARCH
COPY . .
WORKDIR "/src/RelyingParty"
RUN dotnet publish "RelyingParty.csproj" -c Release -o /app/publish /p:UseAppHost=false -a $TARGETARCH


FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine 
EXPOSE 8080
WORKDIR /app
COPY --from=build /app/publish .
USER $APP_UID
ENTRYPOINT ["dotnet", "RelyingParty.dll"]
