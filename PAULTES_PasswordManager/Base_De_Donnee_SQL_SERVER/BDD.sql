USE [master]
GO
/****** Object:  User [##MS_PolicyEventProcessingLogin##]    Script Date: 07/02/2020 14:58:45 ******/
CREATE USER [##MS_PolicyEventProcessingLogin##] FOR LOGIN [##MS_PolicyEventProcessingLogin##] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  User [##MS_AgentSigningCertificate##]    Script Date: 07/02/2020 14:58:45 ******/
CREATE USER [##MS_AgentSigningCertificate##] FOR LOGIN [##MS_AgentSigningCertificate##]
GO
/****** Object:  Table [dbo].[BaseMdps]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[BaseMdps](
	[USER] [nvarchar](250) NOT NULL,
	[ID] [bigint] IDENTITY(1,1) NOT NULL,
	[Email] [nvarchar](250) NOT NULL,
	[Role] [int] NOT NULL,
	[HA] [varchar](500) NULL,
	[Salt] [varbinary](250) NULL,
 CONSTRAINT [PK_BaseMdps] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
 CONSTRAINT [KEY_BaseMdps_ID] UNIQUE NONCLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
 CONSTRAINT [KEY_BaseMdps_USER] UNIQUE NONCLUSTERED 
(
	[USER] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Correspondances]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Correspondances](
	[IDuser] [bigint] NOT NULL,
	[mdp] [nvarchar](250) NOT NULL,
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[ReferenceSite] [varchar](250) NULL,
 CONSTRAINT [PK_Correspondances] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[VueMdpUser]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[VueMdpUser]
AS
SELECT        dbo.BaseMdps.[USER], dbo.Correspondances.mdp, dbo.Correspondances.ReferenceSite, dbo.Correspondances.Id
FROM            dbo.BaseMdps INNER JOIN
                         dbo.Correspondances ON dbo.BaseMdps.ID = dbo.Correspondances.IDuser
GO
/****** Object:  View [dbo].[VueUser]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[VueUser]
AS
SELECT        [USER], Mdp, [Key], Role, Email
FROM            dbo.BaseMdps
GO
ALTER TABLE [dbo].[BaseMdps] ADD  DEFAULT ((0)) FOR [Role]
GO
ALTER TABLE [dbo].[Correspondances]  WITH CHECK ADD  CONSTRAINT [FK_Correspondances_BaseMdps_0] FOREIGN KEY([IDuser])
REFERENCES [dbo].[BaseMdps] ([ID])
GO
ALTER TABLE [dbo].[Correspondances] CHECK CONSTRAINT [FK_Correspondances_BaseMdps_0]
GO
/****** Object:  StoredProcedure [dbo].[sp_AddMdp]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Louis PAULTES
-- Create date: 05/02/2020
-- Description:	Aucune
-- =============================================
CREATE PROCEDURE [dbo].[sp_AddMdp] 
	-- Add the parameters for the stored procedure here
	@Id bigint = 0,
	@site varchar(250) = '',
	@mdp nvarchar(250) = ''
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	INSERT INTO [dbo].[Correspondances]
	([dbo].[Correspondances].[IDuser],[dbo].[Correspondances].[ReferenceSite],[dbo].[Correspondances].[mdp])
	 VALUES (@Id,@site,@mdp);
END
GO
/****** Object:  StoredProcedure [dbo].[sp_CreateUser]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Louis PAULTES
-- Create date: 05/02/2020
-- Description:	Aucune
-- =============================================
CREATE PROCEDURE [dbo].[sp_CreateUser] 
	-- Add the parameters for the stored procedure here
	@User nvarchar(250) = '',
	@email nvarchar(250) = '',
	@HA varchar(500) = '',
	@Salt varbinary(250) 
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
    -- Insert statements for procedure here
	INSERT INTO [dbo].[BaseMdps] 
	([dbo].[BaseMdps].[USER],[dbo].[BaseMdps].[Email],[dbo].[BaseMdps].[Role],[dbo].[BaseMdps].[HA],[dbo].[BaseMdps].[Salt])
	VALUES
	(@User,@email,0,@HA,@Salt);
END
GO
/****** Object:  StoredProcedure [dbo].[sp_DelMdp]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Louis PAULTES
-- Create date: 05/02/2020
-- Description:	Aucune
-- =============================================
CREATE PROCEDURE [dbo].[sp_DelMdp] 
	-- Add the parameters for the stored procedure here
	@Id bigint = 0
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	DELETE FROM [dbo].[Correspondances] WHERE [dbo].[Correspondances].[Id] = @Id;
END
GO
/****** Object:  StoredProcedure [dbo].[sp_GetMdp]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Louis PAULTES
-- Create date: 05/02/2020
-- Description:	Aucune
-- =============================================
CREATE PROCEDURE [dbo].[sp_GetMdp] 
	-- Add the parameters for the stored procedure here
	@User varchar(250) = ''
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	SELECT [dbo].[VueMdpUser].[mdp],[dbo].[VueMdpUser].[ReferenceSite],[dbo].[VueMdpUser].[Id] FROM [dbo].[VueMdpUser] WHERE [dbo].[VueMdpUser].[USER] = @User;
END
GO
/****** Object:  StoredProcedure [dbo].[sp_GetUser]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Louis PAULTES
-- Create date: 05/02/2020
-- Description:	Aucune
-- =============================================
CREATE PROCEDURE [dbo].[sp_GetUser] 
	-- Add the parameters for the stored procedure here
	@User varchar(250) = ''
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
    -- Insert statements for procedure here
	 SELECT * FROM [dbo].[BaseMdps] WHERE [dbo].[BaseMdps].[USER] = @User;
END
GO
/****** Object:  StoredProcedure [dbo].[sp_UpdMdp]    Script Date: 07/02/2020 14:58:46 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Louis PAULTES
-- Create date: 05/02/2020
-- Description:	Aucune
-- =============================================
CREATE PROCEDURE [dbo].[sp_UpdMdp] 
	-- Add the parameters for the stored procedure here

	@Id bigint = 0,
	@Ref varchar(250) = '',
	@mdp nvarchar(250) = ''
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	UPDATE [dbo].[Correspondances] SET [dbo].[Correspondances].[mdp] = @mdp,[dbo].[Correspondances].[ReferenceSite] = @Ref  WHERE [dbo].[Correspondances].[Id] = @Id;
END
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "BaseMdps"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 246
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Correspondances"
            Begin Extent = 
               Top = 6
               Left = 284
               Bottom = 119
               Right = 492
            End
            DisplayFlags = 280
            TopColumn = 1
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'VueMdpUser'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'VueMdpUser'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "BaseMdps"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 246
            End
            DisplayFlags = 280
            TopColumn = 2
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'VueUser'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'VueUser'
GO
