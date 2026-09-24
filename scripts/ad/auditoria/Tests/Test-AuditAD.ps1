#requires -Version 3.0
# Testes offline. Nao consulta AD nem requer Pester/RSAT.
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$source=Join-Path (Split-Path $PSScriptRoot -Parent) 'Audit-ADAdmins.ps1'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw "FALHOU: $Message" } }
# Carrega apenas funcoes, sem executar a coleta.
foreach ($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    Invoke-Expression $f.Extent.Text
}
Assert-True ((Get-AclReasons 131220 '00000000-0000-0000-0000-000000000000') -eq '') 'GenericRead nao deve gerar delegacao'
Assert-True ((Get-AclReasons 983551 '00000000-0000-0000-0000-000000000000') -match 'Controle total') 'GenericAll'
Assert-True ((Get-AclReasons 32 'bf9679c0-0de6-11d0-a285-00aa003049e2') -match 'Escrita de propriedade') 'Escrita de membros'
Assert-True ((Get-AclReasons 256 '00299570-246d-11d0-a768-00aa006e0529') -eq 'Redefinir senha') 'Reset de senha'
Assert-True ((Get-AclReasons 256 'ab721a53-1e2f-11d0-9819-00aa0040529b') -eq '') 'Trocar propria senha nao e reset'
Assert-True ((ConvertTo-SafeCell '=HYPERLINK("x")').StartsWith("'=")) 'Neutralizacao de formula'
Assert-True ((Format-FileTime 0) -eq 'Nao registrado') 'lastLogon zero'
$script:BrasiliaTimeZone=[System.TimeZoneInfo]::FindSystemTimeZoneById('E. South America Standard Time')
$utc=[datetime]::SpecifyKind([datetime]'2026-09-24 01:30:00',[DateTimeKind]::Utc)
Assert-True ((Format-Date $utc) -eq '23/09/2026 22:30') 'Brasilia e virada de dia a partir de UTC'
Assert-True ((Format-FileTime $utc.ToFileTimeUtc()) -eq '23/09/2026 22:30') 'FILETIME em Brasilia'

# DACL sintetica: Allow/Deny sao preservados e somente Allow cria raiz candidata.
Add-Type -AssemblyName System.DirectoryServices
$script:Nodes=@{}; $script:BySid=@{}; $script:Roots=@{}; $script:AclCount=0
$g=[pscustomobject]@{DistinguishedName='CN=Delegados,DC=teste';SID='S-1-5-21-1-2-3-1234';Name='Delegados';SamAccountName='Delegados';GroupCategory='Security'}
[void](Add-Node $g 'teste' 'group')
$scratch=Join-Path $env:TEMP ('AuditAD-Test-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $scratch)
$Delimiter=';'
    $row=[pscustomobject][ordered]@{Principal='';PrincipalDN='';TipoPrincipal='';SID=$g.SID;TipoACE='Deny'}
    Write-AclEvidence $row 'teste' $false
    Assert-True ($script:Roots.Count -eq 0) 'Deny nao concede delegacao'
    $row.TipoACE='Allow'
    Write-AclEvidence $row 'teste' $true
    Assert-True ($script:Roots.Count -eq 1) 'Grupo personalizado com Allow vira candidato'

# Execucao completa com cmdlets AD simulados. O script continua sendo o mesmo entregue.
function Import-Module { [CmdletBinding()]param([string]$Name) if ($Name -ne 'ActiveDirectory') { throw "Importacao inesperada: $Name" } }
$base='DC=teste,DC=local'
$domainSid='S-1-5-21-1-2-3'
function New-TestUser {
    param([string]$Name,[int]$Rid,[int]$Primary=513,[bool]$Enabled=$true)
    [pscustomobject]@{DistinguishedName="CN=$Name,$base";SID="$domainSid-$Rid";Name=('Nome completo ' + $Name);SamAccountName=$Name;Enabled=$Enabled;PasswordLastSet=$utc;lastLogonTimestamp=0;primaryGroupID=$Primary;adminCount=0;SIDHistory=@()}
}
function New-TestGroup {
    param([string]$Name,[string]$Sid,[string[]]$Members,[string]$Category='Security')
    [pscustomobject]@{DistinguishedName="CN=$Name,$base";SID=$Sid;Name=$Name;SamAccountName=$Name;Members=$Members;GroupCategory=$Category;GroupScope='Global';SIDHistory=@()}
}
$mockUsers=@((New-TestUser 'x.y' 1001),(New-TestUser 'primario' 1002 512),(New-TestUser 'comum' 1003),(New-TestUser 'desabilitado' 1004 513 $false),(New-TestUser 'somente_distribuicao' 1005))
$mockGroups=@(
    (New-TestGroup 'Proprietarios criadores de diretiva de grupo' "$domainSid-520" @("CN=comum,$base","CN=x.y,$base")),
    (New-TestGroup 'DA Renomeado' "$domainSid-512" @("CN=TI,$base","CN=Operacoes,$base","CN=Distribuicao,$base")),
    (New-TestGroup 'Administrators' 'S-1-5-32-544' @("CN=DA Renomeado,$base")),
    (New-TestGroup 'TI' "$domainSid-1100" @("CN=x.y,$base","CN=desabilitado,$base","CN=Ciclo,$base","CN=PC,$base")),
    (New-TestGroup 'Operacoes' "$domainSid-1101" @("CN=FSP,$base","CN=PC,$base")),
    (New-TestGroup 'Ciclo' "$domainSid-1102" @("CN=TI,$base")),
    (New-TestGroup 'Domain Users' "$domainSid-513" @()),
    (New-TestGroup 'Distribuicao' "$domainSid-1103" @("CN=somente_distribuicao,$base") 'Distribution')
)
function Get-ADForest { [CmdletBinding()]param($Server) [pscustomobject]@{Name='teste.local';Domains=@('teste.local')} }
function Get-ADDomain { [CmdletBinding()]param($Identity,$Server) [pscustomobject]@{DNSRoot='teste.local';PDCEmulator='dc1.teste.local';DomainSID=$domainSid;DistinguishedName=$base} }
function Get-ADRootDSE { [CmdletBinding()]param($Server) [pscustomobject]@{namingContexts=@($base)} }
function Get-ADGroup { [CmdletBinding()]param($Filter,$Server,$ResultPageSize,$Properties) $mockGroups }
function Get-ADObject {
    [CmdletBinding()]param($Identity,$Server,$Properties)
    if ($Identity -eq "CN=FSP,$base") { [pscustomobject]@{Name='FSP';sAMAccountName=$null;ObjectClass='foreignSecurityPrincipal';objectSid="$domainSid-1001"} }
    elseif ($Identity -eq "CN=PC,$base") { [pscustomobject]@{Name='PC';sAMAccountName='PC$';ObjectClass='computer';objectSid="$domainSid-4001"} }
    else { throw "Objeto inesperado: $Identity" }
}
function Get-ADUser {
    [CmdletBinding()]param($Filter,$Server,$ResultPageSize,$Properties)
    if (@($Properties) -contains 'lastLogon') {
        if ($Server -eq 'dc2.teste.local') { throw 'DC indisponivel (simulado)' }
        foreach ($u in $mockUsers) { [pscustomobject]@{SID=$u.SID;lastLogon=$utc.ToFileTimeUtc()} }
    } else { $mockUsers }
}
function Get-ADDomainController { [CmdletBinding()]param($Filter,$Server) [pscustomobject]@{HostName='dc1.teste.local'}; [pscustomobject]@{HostName='dc2.teste.local'} }
& $source -OutputPath $scratch -SkipAclScan -ExactLastLogon -WarningVariable auditWarnings
$run=Get-ChildItem -LiteralPath $scratch -Directory | Select-Object -First 1
$users=@(Import-Csv -LiteralPath (Join-Path $run.FullName '01-Usuarios.csv') -Delimiter ';')
$groups=@(Import-Csv -LiteralPath (Join-Path $run.FullName '02-GruposAdministrativos.csv') -Delimiter ';')
Assert-True (@(Get-ChildItem -LiteralPath $run.FullName -File).Count -eq 2) 'Exatamente dois arquivos por execucao'
Assert-True (($users[0].PSObject.Properties.Name -join ',') -eq 'Usuario,Estado,Grupos que concedem privilégios,Como o usuário recebe o privilégio,Ultima troca de senha,Último logon registrado') 'Somente seis colunas de usuarios'
Assert-True (($groups[0].PSObject.Properties.Name -join ',') -eq 'Grupo,Contas e grupos incluídos diretamente,Este grupo está incluído em,Total de membros diretos') 'Somente quatro colunas de grupos'
Assert-True ($users.Count -eq 3) 'Somente usuarios administrativos exportados'
Assert-True (($users | ConvertTo-Csv -NoTypeInformation | Out-String) -notmatch 'Group Policy Creator Owners|Proprietarios criadores') 'GPO nao aparece como privilegio ou caminho; membro exclusivo nao e incluido'
$xy=$users | Where-Object {$_.Usuario -eq 'x.y'}
Assert-True ($xy.'Grupos que concedem privilégios' -match 'Domain Admins' -and $xy.'Grupos que concedem privilégios' -match 'Administrators') 'Grupos renomeados por SID e heranca'
Assert-True ($xy.'Como o usuário recebe o privilégio' -match 'TI > Domain Admins' -and $xy.'Como o usuário recebe o privilégio' -match 'Operacoes > Domain Admins') 'Caminhos indiretos preservados inclusive FSP'
Assert-True ($xy.'Como o usuário recebe o privilégio' -notmatch '\\') 'Caminhos sem prefixo de dominio'
Assert-True (($users | Where-Object {$_.Usuario -eq 'primario'}).'Grupos que concedem privilégios' -match 'Domain Admins') 'Grupo primario privilegiado'
Assert-True (@($users | Where-Object {$_.Usuario -eq 'desabilitado'}).Count -eq 1) 'Desabilitados incluidos por padrao'
Assert-True (@($users | Where-Object {$_.Usuario -eq 'somente_distribuicao'}).Count -eq 0) 'Distribuicao nao inclui usuario comum'
Assert-True (@($users | Where-Object {$_.Usuario -eq 'comum'}).Count -eq 0) 'Usuario comum excluido'
Assert-True ($xy.'Último logon registrado' -eq '23/09/2026 22:30' -and $xy.'Ultima troca de senha' -eq '23/09/2026 22:30') 'Datas dos CSVs em Brasilia'
Assert-True (($auditWarnings -join ' ') -match 'DC indisponivel') 'Falha de DC sinalizada no console'
Assert-True (($auditWarnings -join ' ') -match 'Ciclo') 'Ciclo detectado sem loop'
Assert-True (($groups | Where-Object {$_.Grupo -eq 'DA Renomeado'}).'Contas e grupos incluídos diretamente' -match 'TI') 'Resumo com membros diretos'
Assert-True (($groups | Where-Object {$_.Grupo -eq 'TI'}).'Contas e grupos incluídos diretamente' -eq 'x.y | desabilitado | Ciclo | PC$') 'Membros com login ou nome de grupo, sem marcadores'
Assert-True (($groups | Where-Object {$_.Grupo -eq 'TI'}).'Este grupo está incluído em' -notmatch '\\') 'Grupos pais sem dominio'
Assert-True (($groups | Where-Object {$_.Grupo -eq 'TI'}).'Total de membros diretos' -eq '4') 'Contagem dos membros preservada'
$bytes=[System.IO.File]::ReadAllBytes((Join-Path $run.FullName '01-Usuarios.csv'))
Assert-True ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) 'UTF-8 com BOM no Windows PowerShell'
$inclusiveOutput=Join-Path $scratch 'com-desabilitados'
& $source -OutputPath $inclusiveOutput -SkipAclScan -IncludeDisabled
$inclusiveRun=Get-ChildItem -LiteralPath $inclusiveOutput -Directory | Select-Object -First 1
$inclusiveUsers=@(Import-Csv -LiteralPath (Join-Path $inclusiveRun.FullName '01-Usuarios.csv') -Delimiter ';')
Assert-True ($inclusiveUsers.Count -eq 3 -and ($inclusiveUsers | Where-Object {$_.Usuario -eq 'desabilitado'}).Estado -eq 'Desabilitado') 'IncludeDisabled conserva administradores desabilitados'
Assert-True (($xy.'Como o usuário recebe o privilégio' -notmatch 'DA Renomeado') -and ($xy.'Como o usuário recebe o privilégio' -match 'Domain Admins')) 'Grupo padrao renomeado exibido em ingles por SID'
Assert-True (($groups | Where-Object {$_.Grupo -eq 'TI'}).'Este grupo está incluído em' -match 'DA Renomeado') 'Padronizacao tambem nos pais do CSV de grupos'

# Sem administradores: manter somente os dois CSVs, ambos com seus cabecalhos.
$savedUsers=$mockUsers; $savedGroups=$mockGroups
$mockUsers=@($savedUsers | Where-Object {$_.SamAccountName -eq 'comum'})
$mockGroups=@($savedGroups | Where-Object {$_.SamAccountName -eq 'Domain Users'})
$emptyOutput=Join-Path $scratch 'sem-admin'
& $source -OutputPath $emptyOutput -SkipAclScan
$emptyRun=Get-ChildItem -LiteralPath $emptyOutput -Directory | Select-Object -First 1
Assert-True (@(Get-ChildItem -LiteralPath $emptyRun.FullName -File).Count -eq 2) 'Sem resultados ainda gera somente dois arquivos'
Assert-True (@(Import-Csv -LiteralPath (Join-Path $emptyRun.FullName '01-Usuarios.csv') -Delimiter ';').Count -eq 0) 'Nenhum usuario normal exportado na coleta vazia'
Assert-True ((Get-Content -LiteralPath (Join-Path $emptyRun.FullName '01-Usuarios.csv') -TotalCount 1) -eq '"Usuario";"Estado";"Grupos que concedem privilégios";"Como o usuário recebe o privilégio";"Ultima troca de senha";"Último logon registrado"') 'Cabecalho de usuarios preservado sem dados'
Assert-True ((Get-Content -LiteralPath (Join-Path $emptyRun.FullName '02-GruposAdministrativos.csv') -TotalCount 1) -eq '"Grupo";"Contas e grupos incluídos diretamente";"Este grupo está incluído em";"Total de membros diretos"') 'Cabecalho de grupos preservado sem dados'
$mockUsers=$savedUsers; $mockGroups=$savedGroups

# Mesma rotina de caminhos tambem expande uma raiz originada de ACL.
$script:Children=@{}; $script:Parents=@{}; $script:EdgeKeys=@{}
$script:RelevantGroups=@{}; $script:Issues=New-List
$MaxDepth=100; $MaxPathsPerRoot=100000
[void](Add-Node $mockUsers[0] 'teste' 'user')
Add-Edge $g.DistinguishedName $mockUsers[0].DistinguishedName 'member'
$delegatedRoot=@($script:Roots.Values)[0]
$delegatedPaths=@(Get-RootPaths $delegatedRoot)
Assert-True ($delegatedPaths.Count -eq 1 -and $delegatedPaths[0].Tipo -eq 'DelegacaoPotencial') 'Delegacao personalizada chega ao usuario via grupo'
$MaxPathsPerRoot=1
$limited=@(Get-RootPaths $delegatedRoot)
Assert-True ($limited.Count -eq 0 -and $script:Issues[0].Etapa -eq 'LimiteCaminhos') 'Truncamento por limite fica explicito'

# SIDs Builtin se repetem em dominios diferentes; a resolucao deve manter o contexto.
$builtinA=New-TestGroup 'BuiltinA' 'S-1-5-32-544' @()
$builtinB=New-TestGroup 'BuiltinB' 'S-1-5-32-544' @()
[void](Add-Node $builtinA 'dominioA' 'group')
[void](Add-Node $builtinB 'dominioB' 'group')
Assert-True ((Resolve-SidNode 'S-1-5-32-544' 'dominioB').Name -eq 'BuiltinB') 'SID Builtin resolvido no dominio correto'
Assert-True ($null -eq (Resolve-SidNode 'S-1-5-32-544' 'dominioAusente')) 'Builtin de outro dominio nao substitui grupo ausente'
Write-Host "OK: testes offline passaram. Artefatos de teste: $scratch" -ForegroundColor Green


