Configuration AppsConfiguration
{
    param (
        [Bool] $installEkranServer,
        [Bool] $installPGServer,
        [Bool] $installSQLServer,
		[String] $sqlServerType,
        [String] $sqlServerHostname,
        [String] $sqlServerPort,
        [String] $managementToolUrl,
        [String] $subNetPrefix,
        [PSCredential] $sqlServerUser,
        [PSCredential] $mtDefaultUser
	)
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    
    Node localhost
    {
        Script InstallPostgreSQL {
            SetScript = {
                $fileName = "postgresql-13.1-1-windows-x64.exe"
                $filePath = "$env:TEMP\$fileName"

                Get-Disk | Where-Object partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter "G" -UseMaximumSize | Format-Volume -FileSystem NTFS -Confirm:$false
                New-PSDrive -Name "G" -Root "G:\" -PSProvider "FileSystem"
                $dataDir = "G:\PostgreSQL\13\data"

                [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
                Invoke-WebRequest -Uri http://get.enterprisedb.com/postgresql/$fileName -OutFile $filePath -UseBasicParsing
                & "$filePath" --mode unattended --superaccount $Using:sqlServerUser.UserName --superpassword "$($sqlServerUser.GetNetworkCredential().Password)"  --servicepassword "$($sqlServerUser.GetNetworkCredential().Password)" --serverport $Using:sqlServerPort --datadir $dataDir

                $proc = Get-Process -Name $fileName.Substring(0,$fileName.Length-4)
                While ($proc) {
                    if ($proc) {
                        Start-Sleep 10
                        $proc = Get-Process -Name $fileName.Substring(0,$fileName.Length-4) -ErrorAction SilentlyContinue
                    }
                    else {
                        Exit
                    }
                }

                if ( -Not $Using:installEkranServer) {
                    New-NetFirewallRule -DisplayName "PostgreSQLServer" -Direction Inbound -LocalPort $Using:sqlServerPort -Protocol TCP -Action Allow
                    $oldConfig = Get-Content -Path $dataDir\pg_hba.conf
                    Set-Content -Value $oldConfig.Replace('127.0.0.1/32', $Using:subNetPrefix) -Path $dataDir\pg_hba.conf -Force
                    Restart-Service -Name "postgresql*" -Force
                }
            }
            
            TestScript = { 
                $PGService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
                if ($Using:installPGServer -and (-not $PGService)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'PostgreSQL is installed' } }
        }

        Script InstallNetFramework {
            SetScript = {
                $fileName = "ndp48-x86-x64-allos-enu.exe"
                $filePath = "$env:TEMP\$fileName"
                
                [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
                Invoke-WebRequest -Uri https://download.visualstudio.microsoft.com/download/pr/014120d7-d689-4305-befd-3cb711108212/0fd66638cde16859462a6243a4629a50/$fileName -OutFile $filePath -UseBasicParsing

                if ($?) {
	                & "$filePath" '/q' 
                    $proc = Get-Process -Name $fileName.Substring(0,$fileName.Length-4)

                    While ($proc) {
                        Start-Sleep 10
                        $proc = Get-Process -Name $fileName.Substring(0,$fileName.Length-4) -ErrorAction SilentlyContinue
                    }
                }
                else {
	                Throw "ERROR: .NET Framework installation failed"
	
                }
                # Waiting for the host reboot by the .NET installer (usually takes up to 2 min)
                Start-Sleep -Seconds 900
            }
            
            TestScript = { 
                $NetFrameworkReleaseVersion = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
                if ($Using:installEkranServer -and ($NetFrameworkReleaseVersion -lt 528040)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = '.NET Framework version is 4.8.X' } }
            DependsOn = "[Script]InstallPostgreSQL"
        }

        Script DownloadMSCppRedist {
            SetScript = {
                $fileName = "vc_redist.x64.exe"
                $filePath = "$env:TEMP\$fileName"

                [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
                Invoke-WebRequest -Uri https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe -OutFile $filePath -UseBasicParsing
            }
            
            TestScript = { 
                $InstallPackage = Test-Path "$env:TEMP\vc_redist.x64.exe"
                if ($Using:installEkranServer -and (-not $InstallPackage)) {
                    return $false
                }
                else {
                    return $true
                }
            }
                        
            GetScript = { @{ Result = 'Microsoft Visual C++ 2015 Redistributable has been downloaded' } }
            DependsOn = "[Script]InstallNetFramework"
        } 
        
        Script InstallMSCppRedist {
            SetScript = {
                $MSCppRedistFullPath = "$env:TEMP\vc_redist.x64.exe"
                & "$MSCppRedistFullPath" '/passive', '/quite'
            }
            
            TestScript = { 
                $MSCppRedist2015 = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Visual C++ 2015%'"
                if ($Using:installEkranServer -and (-not $MSCppRedist2015)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'Microsoft Visual C++ 2015 Redistributable has been installed' } }
            DependsOn = "[Script]DownloadMSCppRedist"
        }

        Script DownloadEkranServer {
            SetScript = {
                $fileName = "EkranSystem-en.zip"
                $filePath = "$env:TEMP\$fileName"

                [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
                Invoke-WebRequest -Uri https://download.ekransystem.com/EkranSystem-en.zip -OutFile $filePath -UseBasicParsing

                $destination = "$env:TEMP\EkranSystem"
                Expand-Archive -Path $filePath -DestinationPath $destination -Force
            }
            
            TestScript = {
                $InstallPackage = Test-Path "$env:TEMP\EkranSystem"
                if ($Using:installEkranServer -and (-not $InstallPackage)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'EkranServer installation archive was downloaded' } }
            DependsOn = "[Script]InstallLanguagePack"
        } 

        Script CreateIniFile {
		    SetScript = {
                if ($Using:installPGServer -and $Using:installEkranServer) {
                    $sqlInstanceName = 'localhost'
                }
                else {
                    $sqlInstanceName = $Using:sqlServerHostname
                }
                $mtAdminCred = $Using:mtDefaultUser
			    $OFS = "`r`n"
                $ConfigText = 
                "[Database]" +$OFS+ `
                "DBType=" + $Using:sqlServerType +$OFS+ `
                "ServerInstance=" + $sqlInstanceName + ":" + $Using:sqlServerPort +$OFS+ `
                "DBName=EkranActivityDB" +$OFS+ `
                "DBUserName=" + $Using:sqlServerUser.UserName +$OFS+ `
                "DBPassword=" + $sqlServerUser.GetNetworkCredential().Password +$OFS+ `
                "UseExistingDatabase=false" +$OFS+ `
				"Authentication=1" +$OFS+$OFS+ `
                
                "[Admin]" +$OFS+ `
                "AdminPassword=" + $mtAdminCred.GetNetworkCredential().Password +$OFS+$OFS+ `

                "[MT]" +$OFS+ `
                "ServerPath=localhost" +$OFS+ `
                "WebManagementUrl=" + $Using:managementToolUrl

             	$EkranServerDir = (Get-ChildItem -Path "$env:TEMP" -Filter EkranSystem_Server*  -Recurse).Directory
                Set-Content $ConfigText -Path "$EkranServerDir\install.ini"
            }
            
            TestScript = {
                $EkranServerDir = (Get-ChildItem -Path "$env:TEMP" -Filter EkranSystem_Server*  -Recurse -ErrorAction SilentlyContinue).Directory
                $IniFile = Test-Path "$EkranServerDir\install.ini"
                if ($Using:installEkranServer -and (-not $IniFile)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'EkranServer configuration INI file has been created' } }
            DependsOn = "[Script]DownloadEkranServer"
        }

        Script TestMSSQLServer {
            SetScript = {
                $connectionString = "Data Source=$Using:sqlServerHostname,$Using:sqlServerPort;User ID=$($Using:sqlServerUser.UserName);Password=$($sqlServerUser.GetNetworkCredential().Password);"
                $errMessage = "There is no connection to the SQL server. Please check that the SQL server is accessible over the network, and that the correct credentials were provided.`
                Log in to the VM and finish installing the Ekran System Application Server manually. You can find the installation file in $env:TEMP\EkranSystem."
                
                try
                {
                    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString;
                    $sqlConnection.Open();
                    $sqlConnection.Close();
                }
                catch
                {
                    throw $errMessage
                }
            }
            
            TestScript = { -not ((-not $Using:installSQLServer) -and ($Using:sqlServerType -eq 'MSSQL')) }
            GetScript = { @{ Result = 'SQL connection has been tested' } }
            DependsOn = "[Script]CreateIniFile"
        }

        Script TestPGServer {
            SetScript = {
                $fileName = "postgresql-13.1-1-windows-x64.exe"
                $filePath = "$env:TEMP\$fileName"
                $errMessage = "There is no connection to the SQL server. Please check that the SQL server is accessible over the network, and that the correct credentials were provided.`
                Log in to the VM and finish installing the Ekran System Application Server manually. You can find the installation file in $env:TEMP\EkranSystem."

                $psqlFile = Test-Path "$env:PROGRAMFILES\PostgreSQL\13\bin\psql.exe"
                if (-not $psqlFile) {
                    [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
                    Invoke-WebRequest -Uri http://get.enterprisedb.com/postgresql/$fileName -OutFile $filePath -UseBasicParsing
                    & "$filePath" --mode unattended --disable-components server,pgAdmin,stackbuilder
                    $proc = Get-Process -Name $fileName.Substring(0,$fileName.Length-4)
                    While ($proc) {
                        if ($proc) {
                            Start-Sleep 10
                            $proc = Get-Process -Name $fileName.Substring(0,$fileName.Length-4) -ErrorAction SilentlyContinue
                        }
                        else {
                            Exit
                        }
                    }
                }
                $env:PGPASSWORD=$($sqlServerUser.GetNetworkCredential().Password)
                $env:PGUSER=$($Using:sqlServerUser.UserName)
                
                $connectPG = & "$env:PROGRAMFILES\PostgreSQL\13\bin\psql.exe" --host=$Using:sqlServerHostname --port=$Using:sqlServerPort --command="select now()"
                
                Remove-Item -Path Env:PGPASSWORD
                Remove-Item -Path Env:PGUSER

                if (-not $connectPG) {
                    throw $errMessage
                }
            }
            
            TestScript = { -not ((-not $Using:installSQLServer) -and ($Using:sqlServerType -eq 'PG')) }
            
            GetScript = { @{ Result = 'SQL connection has been tested' } }
            DependsOn = "[Script]TestMSSQLServer"
        }

        Script InstallEkranServer {
            SetScript = {
                $EkranServerFullPath = Get-ChildItem -Path "$env:TEMP" -Filter EkranSystem_Server_*  -Recurse | %{$_.FullName}
                & "$EkranServerFullPath" '/S'
                
                $proc = Get-Process -Name "EkranSystem*"
                While ($proc) {
                    if ($proc) {
                        Start-Sleep 10
                        $proc = Get-Process -Name "EkranSystem*" -ErrorAction SilentlyContinue
                    }
                    else {
                        Exit
                    }
                }
            }
            
            TestScript = {
                $ServerProc = Get-Process -Name "EkranServer" -ErrorAction SilentlyContinue
                if ($Using:installEkranServer -and (-not $ServerProc)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'EkranServer has been installed' } }
            DependsOn = "[Script]TestPGServer"
        }

        WindowsFeatureSet ManagementToolRequirements
        {
            Name                    = @("Web-WebServer", "Web-WebSockets", "Web-Asp-Net", "Web-Asp-Net45", "Web-Mgmt-Console")
            Ensure                  = if ($installEkranServer) {'Present'} else { 'Absent' }
            IncludeAllSubFeature    = $true
            DependsOn = "[Script]InstallEkranServer"
        }

        Script CreateSelfSignedCertificate {
            SetScript = {
                
                $site = "Default Web Site"
                
                New-WebBinding -Name $site -IPAddress * -Port 443 -Protocol https
                $cert = New-SelfSignedCertificate -CertStoreLocation 'Cert:\LocalMachine\My' -DnsName "ekransystem"

                $certPath = "Cert:\LocalMachine\My\$($cert.Thumbprint)"
                $providerPath = 'IIS:\SslBindings\0.0.0.0!443'

                Get-Item $certPath | New-Item $providerPath
            }
            
            TestScript = {
                if ($Using:installEkranServer) {
                    $HttpsBinding = Get-WebBinding "Default Web Site" -Protocol https -ErrorAction SilentlyContinue
                    if ($HttpsBinding) {
                        return $true
                    }
                    else {
                        return $false
                    }
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'Self-signed cerificate has been generated' } }
            DependsOn = "[WindowsFeatureSet]ManagementToolRequirements"
        } 
        

        Script InstallEkranMt {
            SetScript = {
                $EkranMtFullPath = Get-ChildItem -Path "$env:TEMP" -Filter EkranSystem_ManagementTool_*  -Recurse | %{$_.FullName}
                & "$EkranMtFullPath" '/S'

                $proc = Get-Process -Name "EkranSystem*"
                While ($proc) {
                    if ($proc) {
                        Start-Sleep 10
                        $proc = Get-Process -Name "EkranSystem*" -ErrorAction SilentlyContinue
                    }
                    else {
                        Exit
                    }
                }
            }
            
            TestScript = {
                if ($Using:installEkranServer) {
                    $mtPool = Get-IISAppPool -Name "EKRANManagementTool"
                    if ($mtPool) {
                        return $true
                    }
                    else {
                        return $false
                    }
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'EkranServer Management Tool has been installed' } }
            DependsOn = "[Script]CreateSelfSignedCertificate"
        }

        Script InstallEkranAgent {
            SetScript = {
                $EkranServerFolder = "C:\Program Files\Ekran System\Ekran System\Server\WinPackage"
                $ConfigText = "[AgentParameters]" + "`r`n" + "RemoteHost=localhost" + "`r`n" + "RemotePort=9447"
                Set-Content $ConfigText -Path "$EkranServerFolder\agent.ini"
                & "$EkranServerFolder\agent.exe"
                $proc = Get-Process -Name "agent*"
                While ($proc) {
                    if ($proc) {
                        Start-Sleep 10
                        $proc = Get-Process -Name "agent*" -ErrorAction SilentlyContinue
                    }
                    else {
                        Exit
                    }
                }
                Restart-Computer -ErrorAction SilentlyContinue
            }
            
            TestScript = {
                $AgentService= Get-Service -Name "EkranClient" -ErrorAction SilentlyContinue
                if ($Using:installEkranServer -and (-not $AgentService)) {
                    return $false
                }
                else {
                    return $true
                }
            }
            
            GetScript = { @{ Result = 'EkranAgent has been installed' } }
            DependsOn = "[Script]InstallEkranMt"
        }
    }
}