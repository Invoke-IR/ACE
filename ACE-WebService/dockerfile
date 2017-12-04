FROM microsoft/aspnetcore-build AS builder
WORKDIR /source
COPY *.csproj .
COPY nuget.config .
RUN dotnet restore
COPY . .
RUN dotnet publish --output /ace/ --configuration Release

FROM microsoft/aspnetcore
WORKDIR /ace
COPY --from=builder /ace .
ENTRYPOINT ["dotnet", "ACEWebService.dll"]