CREATE TABLE [dbo].[Credentials] (
    [Id]       UNIQUEIDENTIFIER NOT NULL,
    [Password] NVARCHAR (MAX)   NOT NULL,
    [UserName] NVARCHAR (MAX)   NOT NULL,
    CONSTRAINT [PK_Credentials] PRIMARY KEY CLUSTERED ([Id] ASC)
);

CREATE TABLE [dbo].[Computers] (
    [Id]              UNIQUEIDENTIFIER NOT NULL,
    [ComputerName]    NVARCHAR (MAX)   NULL,
    [CredentialId]    UNIQUEIDENTIFIER NOT NULL,
    [OperatingSystem] NVARCHAR (MAX)   NULL,
    [RPC]             BIT              NOT NULL,
    [SMB]             BIT              NOT NULL,
    [SSH]             BIT              NOT NULL,
    [Scanned]         BIT              NOT NULL,
    [WinRM]           BIT              NOT NULL,
    CONSTRAINT [PK_Computers] PRIMARY KEY CLUSTERED ([Id] ASC),
    CONSTRAINT [FK_Computers_Credentials_CredentialId] FOREIGN KEY ([CredentialId]) REFERENCES [dbo].[Credentials] ([Id]) ON DELETE CASCADE
);

GO
CREATE NONCLUSTERED INDEX [IX_Computers_CredentialId]
    ON [dbo].[Computers]([CredentialId] ASC);

CREATE TABLE [dbo].[Scans] (
    [Id]              UNIQUEIDENTIFIER NOT NULL,
    [ComputerId]      UNIQUEIDENTIFIER NOT NULL,
    [StartTime]       DATETIME2 (7)    NOT NULL,
    [Status]          NVARCHAR (MAX)   NULL,
    [StopTime]        DATETIME2 (7)    NOT NULL,
    [SweepIdentifier] UNIQUEIDENTIFIER DEFAULT ('00000000-0000-0000-0000-000000000000') NOT NULL,
    CONSTRAINT [PK_Scans] PRIMARY KEY CLUSTERED ([Id] ASC),
    CONSTRAINT [FK_Scans_Computers_ComputerId] FOREIGN KEY ([ComputerId]) REFERENCES [dbo].[Computers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[Scripts] (
    [Id]             UNIQUEIDENTIFIER NOT NULL,
    [CreationTime]   DATETIME2 (7)    NOT NULL,
    [Language]       NVARCHAR (MAX)   NOT NULL,
    [LastUpdateTime] DATETIME2 (7)    NOT NULL,
    [Name]           NVARCHAR (MAX)   NOT NULL,
    [Uri]            NVARCHAR (MAX)   NOT NULL,
    [Enrichment]     NVARCHAR (MAX)   DEFAULT (N'') NOT NULL,
    [Output]         NVARCHAR (MAX)   DEFAULT (N'') NOT NULL,
    CONSTRAINT [PK_Scripts] PRIMARY KEY CLUSTERED ([Id] ASC)
);

CREATE TABLE [dbo].[Downloads] (
    [Id]           UNIQUEIDENTIFIER NOT NULL,
    [AccessedTime] DATETIME2 (7)    NOT NULL,
    [BornTime]     DATETIME2 (7)    NOT NULL,
    [ComputerName] NVARCHAR (MAX)   NOT NULL,
    [DownloadTime] DATETIME2 (7)    NOT NULL,
    [FullPath]     NVARCHAR (MAX)   NOT NULL,
    [ModifiedTime] DATETIME2 (7)    NOT NULL,
    [Name]         NVARCHAR (MAX)   NOT NULL,
    CONSTRAINT [PK_Downloads] PRIMARY KEY CLUSTERED ([Id] ASC)
);

CREATE TABLE [dbo].[Schedules] (
    [Id]             UNIQUEIDENTIFIER NOT NULL,
    [ExecutionCount] INT              NOT NULL,
    [StartTime]      DATETIME2 (7)    NOT NULL,
    [JobName]        NVARCHAR (MAX)   NULL,
    [TriggerName]    NVARCHAR (MAX)   NULL,
    [ScriptId]       NVARCHAR (MAX)   NULL,
    [RepeatCount]    INT              DEFAULT ((0)) NOT NULL,
    CONSTRAINT [PK_Schedules] PRIMARY KEY CLUSTERED ([Id] ASC)
);

CREATE TABLE [dbo].[Sweeps] (
    [Id]            UNIQUEIDENTIFIER NOT NULL,
    [CompleteCount] INT              NOT NULL,
    [EndTime]       DATETIME2 (7)    NOT NULL,
    [ScanCount]     INT              NOT NULL,
    [StartTime]     DATETIME2 (7)    NOT NULL,
    [Status]        NVARCHAR (MAX)   NULL,
    [ErrorCount]    INT              DEFAULT ((0)) NOT NULL,
    CONSTRAINT [PK_Sweeps] PRIMARY KEY CLUSTERED ([Id] ASC)
);

CREATE TABLE [dbo].[Users] (
    [Id]        UNIQUEIDENTIFIER NOT NULL,
    [ApiKey]    NVARCHAR (MAX)   NOT NULL,
    [FirstName] NVARCHAR (MAX)   NULL,
    [IsAdmin]   BIT              NOT NULL,
    [LastName]  NVARCHAR (MAX)   NULL,
    [UserName]  NVARCHAR (MAX)   NOT NULL,
    CONSTRAINT [PK_Users] PRIMARY KEY CLUSTERED ([Id] ASC)
);

INSERT INTO [dbo].[Users] ([Id], [ApiKey], [FirstName], [IsAdmin], [LastName], [UserName]) VALUES (N'334d89c9-da7a-43e8-a648-5dc8b22019ed', N'[APIKEY]', N'Admin', 1, N'Admin', N'admin')