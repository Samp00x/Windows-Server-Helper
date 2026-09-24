#requires -Version 3.0
<#
.SYNOPSIS
Auditoria somente leitura de privilegios, aninhamentos e delegacoes no AD.
.DESCRIPTION
Windows PowerShell 3.0+ / Windows Server 2012+. Requer modulo ActiveDirectory.
Por padrao inventaria todos os dominios da floresta e examina as ACLs das
particoes de dominio, Configuration, Schema e particoes de aplicacao anunciadas
pelos DCs selecionados. Nao calcula acesso efetivo: delegacoes sao candidatas.
Veja LEIA-ME.md para limites, colunas e exemplos.
.EXAMPLE
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -ExactLastLogon
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string[]]$Domains,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Relatorios'),
    [switch]$ExactLastLogon,
    [switch]$IncludeDisabled = $true,
    [switch]$SkipAclScan,
    [ValidateRange(1,512)][int]$MaxDepth = 100,
    [ValidateRange(1,10000000)][int]$MaxPathsPerRoot = 100000,
    [char]$Delimiter = ';'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
Add-Type -AssemblyName System.DirectoryServices
$script:BrasiliaTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById('E. South America Standard Time')

function New-List { return ,(New-Object 'System.Collections.Generic.List[object]') }
function Add-Issue {
    param([string]$Stage, [string]$Target, [string]$Message)
    $script:Issues.Add([pscustomobject][ordered]@{
        Etapa=$Stage; Alvo=$Target; Mensagem=$Message
    })
    Write-Warning ("{0}: {1} - {2}" -f $Stage,$Target,$Message)
}
function ConvertTo-SafeCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    # Impede que nomes controlados no AD sejam tratados como formulas pelo Excel.
    if ($s -match '^[\s]*[=+@-]' -or $s -match '^[\t\r\n]') { return "'" + $s }
    return $s
}
function Export-Report {
    param([string]$Name, [string[]]$Columns, [object[]]$Rows, [hashtable]$DisplayNames = @{})
    $path = Join-Path $script:RunPath $Name
    if ($Rows.Count -eq 0) {
        $header = ($Columns | ForEach-Object {
            $label = $_
            if ($DisplayNames.ContainsKey($_)) { $label = $DisplayNames[$_] }
            '"' + $label.Replace('"','""') + '"'
        }) -join $Delimiter
        Set-Content -LiteralPath $path -Value $header -Encoding UTF8
        return
    }
    $Rows | ForEach-Object {
        $row = $_
        $record = [ordered]@{}
        foreach ($c in $Columns) {
            $label = $c
            if ($DisplayNames.ContainsKey($c)) { $label = $DisplayNames[$c] }
            $record[$label] = ConvertTo-SafeCell $row.$c
        }
        [pscustomobject]$record
    } | Export-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8 -NoTypeInformation
}
function Format-Date {
    param($Value)
    if ($null -eq $Value) { return 'Nao informado' }
    $localDate = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]$Value).ToUniversalTime(), $script:BrasiliaTimeZone)
    return $localDate.ToString('dd/MM/yyyy HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
}
function Format-FileTime {
    param($Value)
    if ($null -eq $Value -or [long]$Value -le 0) { return 'Nao registrado' }
    return Format-Date ([datetime]::FromFileTimeUtc([long]$Value))
}
function Add-Node {
    param($Object, [string]$Domain, [string]$Kind)
    $dn = [string]$Object.DistinguishedName
    $sid = [string]$Object.SID
    $node = [pscustomobject]@{
        DN=$dn; SID=$sid; Name=[string]$Object.Name; Sam=[string]$Object.SamAccountName
        Domain=$Domain; Kind=$Kind; Data=$Object
        Security=($Kind -ne 'group' -or [string]$Object.GroupCategory -eq 'Security')
    }
    $script:Nodes[$dn] = $node
    if (-not $script:BySid.ContainsKey($sid)) { $script:BySid[$sid] = New-List }
    $script:BySid[$sid].Add($node)
    return $node
}
function Resolve-SidNode {
    param([string]$Sid, [string]$Domain)
    if ($script:BySid.ContainsKey($Sid)) {
        $local = @($script:BySid[$Sid] | Where-Object { $_.Domain -eq $Domain })
        if ($local.Count -eq 1) { return $local[0] }
        # Builtin e local ao dominio; nao reutilizar o SID de outro dominio.
        if ($Sid -notlike 'S-1-5-32-*' -and $script:BySid[$Sid].Count -eq 1) { return $script:BySid[$Sid][0] }
    }
    return $null
}
function Add-Edge {
    param([string]$Parent, [string]$Child, [string]$Type)
    $key = $Parent + '|' + $Child
    if ($script:EdgeKeys.ContainsKey($key)) { return }
    $script:EdgeKeys[$key] = $true
    if (-not $script:Children.ContainsKey($Parent)) { $script:Children[$Parent] = New-List }
    $script:Children[$Parent].Add([pscustomobject]@{ Child=$Child; Type=$Type })
    if (-not $script:Parents.ContainsKey($Child)) { $script:Parents[$Child] = New-List }
    $script:Parents[$Child].Add($Parent)
}
function Add-Root {
    param([string]$DN, [string]$Type, [string]$Label)
    $key = $DN + '|' + $Type
    if (-not $script:Roots.ContainsKey($key)) {
        $script:Roots[$key] = [pscustomobject]@{ DN=$DN; Type=$Type; Label=$Label; EvidenceCount=0 }
    }
    return $script:Roots[$key]
}
function Get-AclReasons {
    param([long]$Rights, [string]$ObjectType)
    $reasons = New-List
    # Testar mascaras compostas por igualdade; GenericAll/GenericWrite nao sao bits isolados.
    if (($Rights -band 983551) -eq 983551) { $reasons.Add('Controle total') }
    elseif (($Rights -band 131112) -eq 131112) { $reasons.Add('Escrita generica') }
    if (($Rights -band 262144) -ne 0) { $reasons.Add('Alterar DACL') }
    if (($Rights -band 524288) -ne 0) { $reasons.Add('Alterar proprietario') }
    if (($Rights -band 32) -ne 0) { $reasons.Add('Escrita de propriedade; revisar atributo/escopo') }
    if (($Rights -band 3) -ne 0) { $reasons.Add('Criar/excluir objetos; revisar classe/escopo') }
    if (($Rights -band 65600) -ne 0) { $reasons.Add('Excluir objeto/arvore') }
    if (($Rights -band 8) -ne 0) { $reasons.Add('Escrita validada; revisar escopo') }
    if (($Rights -band 256) -ne 0) {
        switch ($ObjectType.ToLowerInvariant()) {
            '00299570-246d-11d0-a768-00aa006e0529' { $reasons.Add('Redefinir senha') }
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' { $reasons.Add('Replicacao: Get Changes; isolado nao comprova DCSync') }
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' { $reasons.Add('Replicacao: Get Changes All; revisar conjunto/escopo') }
            '89e95b76-444d-4c62-991a-0facbeda640c' { $reasons.Add('Replicacao: Filtered Set') }
            '00000000-0000-0000-0000-000000000000' { $reasons.Add('Todos os direitos estendidos') }
            'ab721a53-1e2f-11d0-9819-00aa0040529b' { } # Trocar a propria senha e rotina, nao reset.
            default { $reasons.Add('Direito estendido; revisar GUID') }
        }
    }
    return ($reasons -join ' | ')
}
function Get-Label {
    param([string]$DN, [switch]$OriginalName)
    if ($script:Nodes.ContainsKey($DN)) {
        $n = $script:Nodes[$DN]
        if ($n.Kind -eq 'user') { return $n.Sam }
        $roleKey = $DN + '|GrupoPrivilegiado'
        if (-not $OriginalName -and $script:Roots.ContainsKey($roleKey)) { return $script:Roots[$roleKey].Label }
        return $n.Name
    }
    if ($script:ExternalLabels.ContainsKey($DN)) { return $script:ExternalLabels[$DN] }
    return 'Membro nao resolvido'
}
function Get-RootPaths {
    param($Root)
    # Caminhos simples por ramo: visitar um grupo em outro ramo e permitido.
    # Assim preservamos TI > DA e Operacoes > DA para um mesmo usuario.
    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{ DN=$Root.DN; Trail=@($Root.DN); Types=@(); Depth=0 })
    $steps = 0
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $steps++
        if ($steps -gt $MaxPathsPerRoot) {
            Add-Issue 'LimiteCaminhos' $Root.DN 'Busca interrompida; resultados parciais. Aumente MaxPathsPerRoot.'
            break
        }
        if (-not $script:Nodes.ContainsKey($item.DN)) { continue }
        $node = $script:Nodes[$item.DN]
        if ($node.Kind -eq 'user') {
            $trail = @($item.Trail)
            [array]::Reverse($trail)
            $labels = @($trail | ForEach-Object { Get-Label $_ })
            $groupTrail = @($trail | Where-Object { $script:Nodes[$_].Kind -eq 'group' })
            [pscustomobject]@{
                UserDN=$node.DN; RootDN=$Root.DN; Tipo=$Root.Type; Privilegio=$Root.Label
                Caminho=($labels -join ' > ')
                CaminhoGrupos=(($groupTrail | ForEach-Object { Get-Label $_ }) -join ' > ')
                Vinculos=($item.Types -join ' | ')
            }
            continue
        }
        if ($node.Kind -ne 'group' -or -not $node.Security) { continue }
        $script:RelevantGroups[$node.DN] = $true
        if (-not $script:Children.ContainsKey($item.DN)) { continue }
        if ($item.Depth -ge $MaxDepth) {
            Add-Issue 'LimiteProfundidade' $item.DN 'Busca interrompida; resultados parciais. Aumente MaxDepth.'
            continue
        }
        foreach ($edge in $script:Children[$item.DN]) {
            if ($item.Trail -contains $edge.Child) {
                Add-Issue 'Ciclo' $edge.Child (($item.Trail + @($edge.Child)) -join ' > ')
                continue
            }
            $stack.Push([pscustomobject]@{
                DN=$edge.Child; Trail=@($item.Trail) + @($edge.Child)
                Types=@($item.Types) + @($edge.Type); Depth=($item.Depth + 1)
            })
        }
    }
}
function Write-AclEvidence {
    param($Row, [string]$Domain, [bool]$Candidate)
    $node = Resolve-SidNode $Row.SID $Domain
    $Row.Principal = $Row.SID
    $Row.PrincipalDN = ''
    $Row.TipoPrincipal = 'Nao resolvido / identidade especial'
    if ($null -ne $node) {
        $Row.Principal = Get-Label $node.DN
        $Row.PrincipalDN = $node.DN
        $Row.TipoPrincipal = $node.Kind
        if ($Candidate -and ($node.Kind -eq 'user' -or ($node.Kind -eq 'group' -and $node.Security))) {
            $root = Add-Root $node.DN 'DelegacaoPotencial' ('Delegacao via ' + (Get-Label $node.DN))
            $root.EvidenceCount++
        }
    }
    # Evidencias servem apenas a avisos de revisao. Nao gerar arquivo extra nem
    # confundir uma delegacao potencial com associacao a grupo privilegiado.
    $script:AclCount++
}
function Scan-AclPartition {
    param([string]$DC, [string]$Base, [string]$Domain)
    $entry = $null; $searcher = $null; $results = $null
    $read = 0; $missing = 0
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC/$Base")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = '(objectClass=*)'
        $searcher.PageSize = 500
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
        foreach ($p in @('distinguishedName','ntSecurityDescriptor','objectClass')) { [void]$searcher.PropertiesToLoad.Add($p) }
        $results = $searcher.FindAll()
        foreach ($result in $results) {
            $dn = [string]$result.Properties['distinguishedname'][0]
            if ($result.Properties['ntsecuritydescriptor'].Count -eq 0) {
                $missing++
                Add-Issue 'ACLSemDescritor' $dn 'Descritor nao retornado; verificar permissao de leitura.'
                continue
            }
            try {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm([byte[]]$result.Properties['ntsecuritydescriptor'][0])
                $read++
                $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
                if ($null -ne $owner) {
                    Write-AclEvidence ([pscustomobject][ordered]@{
                        Principal=''; PrincipalDN=''; TipoPrincipal=''; SID=$owner.Value
                        Dominio=$Domain; DC=$DC; ObjetoDN=$dn; Classe=([string]$result.Properties['objectclass'][-1])
                        TipoACE='Owner'; Direitos='Proprietario'; Motivo='Proprietario; revisar controle da DACL e OWNER RIGHTS'
                        ObjectType=''; InheritedObjectType=''; Herdada=''; Heranca=''; Propagacao=''
                        Aplicacao='Propriedade do objeto; acesso efetivo nao calculado'
                    }) $Domain $true
                }
                foreach ($ace in $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
                    $reason = Get-AclReasons ([long]$ace.ActiveDirectoryRights) $ace.ObjectType.ToString()
                    if (-not $reason) { continue }
                    $inheritOnly = (([int]$ace.PropagationFlags -band 2) -ne 0)
                    $application = 'Revisar objeto, GUIDs, heranca e Deny; acesso efetivo nao calculado'
                    if ($inheritOnly) { $application = 'Somente descendentes; nao se aplica ao proprio objeto' }
                    Write-AclEvidence ([pscustomobject][ordered]@{
                        Principal=''; PrincipalDN=''; TipoPrincipal=''; SID=$ace.IdentityReference.Value
                        Dominio=$Domain; DC=$DC; ObjetoDN=$dn; Classe=([string]$result.Properties['objectclass'][-1])
                        TipoACE=[string]$ace.AccessControlType; Direitos=[string]$ace.ActiveDirectoryRights; Motivo=$reason
                        ObjectType=$ace.ObjectType.ToString(); InheritedObjectType=$ace.InheritedObjectType.ToString()
                        Herdada=$ace.IsInherited; Heranca=[string]$ace.InheritanceType; Propagacao=[string]$ace.PropagationFlags
                        Aplicacao=$application
                    }) $Domain ($ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
                }
            } catch { Add-Issue 'ACLObjeto' $dn $_.Exception.Message }
        }
        $script:Coverage.Add([pscustomobject]@{ Etapa='ACL'; Alvo=$Base; DC=$DC; Status='Concluido'; Quantidade=$read; Observacao="Descritores ausentes: $missing" })
    } catch {
        Add-Issue 'ACLParticao' $Base $_.Exception.Message
        $script:Coverage.Add([pscustomobject]@{ Etapa='ACL'; Alvo=$Base; DC=$DC; Status='Falha/parcial'; Quantidade=$read; Observacao=$_.Exception.Message })
    } finally {
        if ($null -ne $results) { $results.Dispose() }
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $entry) { $entry.Dispose() }
    }
}

$script:Issues=New-List; $script:Coverage=New-List
$script:Nodes=@{}; $script:BySid=@{}; $script:Children=@{}; $script:Parents=@{}; $script:ExternalLabels=@{}
$script:EdgeKeys=@{}; $script:Roots=@{}; $script:RelevantGroups=@{}
$domainContexts=New-List; $allUsers=New-List; $allGroups=New-List
$unresolved=New-List; $paths=New-List; $lastLogons=@{}; $logonStatus=@{}
$start = Get-Date
$script:RunPath = Join-Path $OutputPath ('AD-{0}-{1}' -f $start.ToString('yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
[void](New-Item -ItemType Directory -Path $script:RunPath -Force)
$connection=@{}
if ($Server) { $connection.Server=$Server }
$forest = Get-ADForest @connection
if (-not $Domains -or $Domains.Count -eq 0) { $Domains=@($forest.Domains) }
foreach ($domainName in $Domains) {
    Write-Host "Inventariando dominio $domainName ..."
    try {
        $domain = Get-ADDomain -Identity $domainName -Server $domainName
        $dc = [string]$domain.PDCEmulator
        $rootDse = Get-ADRootDSE -Server $dc
        # Materializar antes de alterar o inventario evita tratar coleta parcial como completa.
        $users = @(Get-ADUser -Filter * -Server $dc -ResultPageSize 500 -Properties Enabled,PasswordLastSet,lastLogonTimestamp,primaryGroupID,adminCount,SIDHistory)
        $groups = @(Get-ADGroup -Filter * -Server $dc -ResultPageSize 500 -Properties Members,GroupCategory,GroupScope,SIDHistory)
        foreach ($u in $users) { $allUsers.Add((Add-Node $u $domain.DNSRoot 'user')) }
        foreach ($g in $groups) { $allGroups.Add((Add-Node $g $domain.DNSRoot 'group')) }
        $domainContexts.Add([pscustomobject]@{ Domain=$domain; DC=$dc; RootDSE=$rootDse })
        $script:Coverage.Add([pscustomobject]@{ Etapa='Inventario'; Alvo=$domain.DNSRoot; DC=$dc; Status='Concluido'; Quantidade=$users.Count; Observacao=("Usuarios: {0}; grupos: {1}" -f $users.Count,$groups.Count) })
    } catch {
        Add-Issue 'Inventario' $domainName $_.Exception.Message
        $script:Coverage.Add([pscustomobject]@{ Etapa='Inventario'; Alvo=$domainName; DC=''; Status='Falha'; Quantidade=0; Observacao=$_.Exception.Message })
    }
}
if ($domainContexts.Count -eq 0) { throw 'Nenhum dominio foi inventariado. Verifique acesso, RSAT, DNS e conectividade.' }

Write-Host 'Montando vinculos de todos os grupos, incluindo grupos primarios ...'
$fspCache=@{}
foreach ($group in $allGroups) {
    foreach ($memberDN in $group.Data.Members) {
        $child=[string]$memberDN
        if (-not $script:Nodes.ContainsKey($child)) {
            if (-not $fspCache.ContainsKey($child)) {
                $resolved=$null
                try {
                    $ctx = $domainContexts | Where-Object { $_.Domain.DNSRoot -eq $group.Domain } | Select-Object -First 1
                    $obj=Get-ADObject -Identity $child -Server $ctx.DC -Properties objectSid,sAMAccountName
                    $label=[string]$obj.Name
                    if ($obj.sAMAccountName) { $label=[string]$obj.sAMAccountName }
                    $script:ExternalLabels[$child]=$label
                    if ([string]$obj.ObjectClass -eq 'foreignSecurityPrincipal') {
                        $resolved=Resolve-SidNode ([string]$obj.objectSid) $group.Domain
                    }
                    $memberClass=[string]$obj.ObjectClass
                    $memberNote='Nao expandido: objeto fora do inventario, computador, conta de servico ou principal externo.'
                } catch {
                    Add-Issue 'Membro' $child $_.Exception.Message
                    $memberClass='Desconhecida'; $memberNote=$_.Exception.Message
                }
                $fspCache[$child]=[pscustomobject]@{ Node=$resolved; Class=$memberClass; Note=$memberNote }
            }
            if ($null -ne $fspCache[$child].Node) { $child=$fspCache[$child].Node.DN }
            else {
                $unresolved.Add([pscustomobject]@{ GrupoDN=$group.DN; MembroDN=$child; Classe=$fspCache[$child].Class; Observacao=$fspCache[$child].Note })
            }
        }
        Add-Edge $group.DN $child 'member'
    }
}
foreach ($u in $allUsers) {
    $primarySid = $u.SID.Substring(0,$u.SID.LastIndexOf('-')) + '-' + [string]$u.Data.primaryGroupID
    $primary = Resolve-SidNode $primarySid $u.Domain
    if ($null -ne $primary) { Add-Edge $primary.DN $u.DN 'primaryGroupID' }
    else { Add-Issue 'GrupoPrimario' $u.DN ("Grupo nao resolvido: $primarySid") }
}

# RIDs/SIDs independem do idioma e de renomeacao dos grupos padrao.
$domainRoles=@{512='Domain Admins';518='Schema Admins';519='Enterprise Admins';526='Key Admins';527='Enterprise Key Admins'}
$builtinRoles=@{544='Administrators';548='Account Operators';549='Server Operators';550='Print Operators';551='Backup Operators'}
foreach ($ctx in $domainContexts) {
    foreach ($rid in $domainRoles.Keys) {
        $n=Resolve-SidNode (([string]$ctx.Domain.DomainSID) + '-' + $rid) $ctx.Domain.DNSRoot
        if ($null -ne $n) { [void](Add-Root $n.DN 'GrupoPrivilegiado' $domainRoles[$rid]) }
    }
    foreach ($rid in $builtinRoles.Keys) {
        $n=Resolve-SidNode ('S-1-5-32-' + $rid) $ctx.Domain.DNSRoot
        if ($null -ne $n) { [void](Add-Root $n.DN 'GrupoPrivilegiado' $builtinRoles[$rid]) }
    }
}
foreach ($g in $allGroups) {
    if ($g.Sam -eq 'DnsAdmins' -and $g.Security) { [void](Add-Root $g.DN 'GrupoPrivilegiado' 'DnsAdmins') }
}

$script:AclCount=0
if (-not $SkipAclScan) {
    Write-Host 'Examinando ACLs; esta etapa pode demorar em diretorios grandes ...'
    $scanned=@{}
    foreach ($ctx in $domainContexts) {
        $bases=@($ctx.Domain.DistinguishedName) + @($ctx.RootDSE.namingContexts)
        foreach ($base in $bases) {
            if (-not $scanned.ContainsKey([string]$base)) {
                $scanned[[string]$base]=$true
                Write-Host "  ACL: $base"
                Scan-AclPartition $ctx.DC ([string]$base) $ctx.Domain.DNSRoot
            }
        }
    }
} else { Add-Issue 'ACL' 'Todas as particoes' 'Varredura desativada por SkipAclScan; grupos personalizados so serao detectados por aninhamento.' }

if ($ExactLastLogon) {
    foreach ($ctx in $domainContexts) {
        $dns=[string]$ctx.Domain.DNSRoot
        $success=0; $expected=0; $failed=$false
        try {
            $dcs=@(Get-ADDomainController -Filter * -Server $ctx.DC)
            $expected=$dcs.Count
            foreach ($dc in $dcs) {
                Write-Host "Consultando lastLogon em $($dc.HostName) ..."
                try {
                    $dcUsers=@(Get-ADUser -Filter * -Server $dc.HostName -Properties lastLogon -ResultPageSize 500)
                    foreach ($u in $dcUsers) {
                        $key=[string]$u.SID
                        if (-not $lastLogons.ContainsKey($key) -or [long]$u.lastLogon -gt $lastLogons[$key]) { $lastLogons[$key]=[long]$u.lastLogon }
                    }
                    $success++
                    $script:Coverage.Add([pscustomobject]@{Etapa='LastLogon';Alvo=$dns;DC=$dc.HostName;Status='Concluido';Quantidade=$dcUsers.Count;Observacao=''})
                } catch {
                    $failed=$true
                    Add-Issue 'LastLogon' $dc.HostName $_.Exception.Message
                    $script:Coverage.Add([pscustomobject]@{Etapa='LastLogon';Alvo=$dns;DC=$dc.HostName;Status='Falha';Quantidade=0;Observacao=$_.Exception.Message})
                }
            }
        } catch { $failed=$true; Add-Issue 'ListarDCs' $dns $_.Exception.Message }
        $state="lastLogon: $success/$expected DCs consultados"
        if ($failed -or $expected -eq 0) { $state += '; PARCIAL' }
        else { $state += '; maior valor dos DCs atuais' }
        $logonStatus[$dns]=$state
        Write-Host ("{0}: {1}" -f $dns,$state)
    }
} else {
    Write-Host 'UltimoLogon usa lastLogonTimestamp (aproximado). Use -ExactLastLogon para consultar todos os DCs.'
}

Write-Host 'Calculando caminhos de privilegio ...'
foreach ($root in @($script:Roots.Values | Where-Object { $_.Type -eq 'GrupoPrivilegiado' } | Sort-Object DN)) {
    foreach ($path in @(Get-RootPaths $root)) { $paths.Add($path) }
}
$pathsByUser=@{}
foreach ($p in $paths) {
    if (-not $pathsByUser.ContainsKey($p.UserDN)) { $pathsByUser[$p.UserDN]=New-List }
    $pathsByUser[$p.UserDN].Add($p)
}
$userRows=New-List
foreach ($u in ($allUsers | Sort-Object Domain,Sam)) {
    if (-not $IncludeDisabled -and -not $u.Data.Enabled) { continue }
    $userPaths=@()
    if ($pathsByUser.ContainsKey($u.DN)) { $userPaths=@($pathsByUser[$u.DN].ToArray()) }
    $standard=@($userPaths | Where-Object { $_.Tipo -eq 'GrupoPrivilegiado' })
    if ($standard.Count -eq 0) { continue }
    $last=Format-FileTime $u.Data.lastLogonTimestamp
    if ($ExactLastLogon) {
        if ($lastLogons.ContainsKey($u.SID)) { $last=Format-FileTime $lastLogons[$u.SID] }
        else { $last='Nao obtido nos DCs consultados' }
    }
    $enabled='Desabilitado'
    if ($u.Data.Enabled) { $enabled='Habilitado' }
    $userRows.Add([pscustomobject][ordered]@{
        Usuario=$u.Sam; Estado=$enabled
        GruposPrivilegiados=(($standard | Select-Object -ExpandProperty Privilegio -Unique) -join ' | ')
        CaminhosGrupos=(($standard | Select-Object -ExpandProperty CaminhoGrupos -Unique) -join ' | ')
        UltimaTrocaSenha=(Format-Date $u.Data.PasswordLastSet); UltimoLogon=$last
    })
}
$userColumns=@('Usuario','Estado','GruposPrivilegiados','CaminhosGrupos','UltimaTrocaSenha','UltimoLogon')
Export-Report '01-Usuarios.csv' $userColumns @($userRows | Sort-Object GruposPrivilegiados,Usuario) @{
    GruposPrivilegiados='Grupos que concedem privilégios'
    CaminhosGrupos='Como o usuário recebe o privilégio'
    UltimaTrocaSenha='Ultima troca de senha'
    UltimoLogon='Último logon registrado'
}

$groupRows=New-List
foreach ($g in ($allGroups | Sort-Object Domain,Name)) {
    $edges=@()
    if ($script:Children.ContainsKey($g.DN)) { $edges=@($script:Children[$g.DN].ToArray()) }
    $parentsOfGroup=@()
    if ($script:Parents.ContainsKey($g.DN)) { $parentsOfGroup=@($script:Parents[$g.DN].ToArray()) }
    if ($script:RelevantGroups.ContainsKey($g.DN)) {
        $groupRows.Add([pscustomobject][ordered]@{
            Grupo=(Get-Label $g.DN -OriginalName)
            MembrosDiretos=(($edges | ForEach-Object { Get-Label $_.Child -OriginalName }) -join ' | ')
            MembroDe=(($parentsOfGroup | ForEach-Object { Get-Label $_ -OriginalName }) -join ' | ')
            QuantidadeMembrosDiretos=$edges.Count
        })
    }
}
Export-Report '02-GruposAdministrativos.csv' @('Grupo','MembrosDiretos','MembroDe','QuantidadeMembrosDiretos') @($groupRows | Sort-Object Grupo) @{
    MembrosDiretos='Contas e grupos incluídos diretamente'
    MembroDe='Este grupo está incluído em'
    QuantidadeMembrosDiretos='Total de membros diretos'
}
foreach ($candidate in @($script:Roots.Values | Where-Object { $_.Type -eq 'DelegacaoPotencial' } | Sort-Object DN)) {
    if (-not $script:RelevantGroups.ContainsKey($candidate.DN) -and -not $pathsByUser.ContainsKey($candidate.DN)) {
        Write-Warning ("Delegacao potencial fora do filtro de grupos administrativos: {0}. Revisar ACL no AD; nao incluida automaticamente nos CSVs." -f $candidate.DN)
    }
}
foreach ($member in $unresolved) {
    Write-Warning ("Membro nao expandido: {0}; grupo: {1}; {2}" -f $member.MembroDN,$member.GrupoDN,$member.Observacao)
}
Write-Host ("Usuarios administrativos exportados: {0}; grupos relacionados: {1}. Datas no horario de Brasilia (dd/MM/yyyy HH:mm)." -f $userRows.Count,$groupRows.Count)
Write-Host ("Concluido. Relatorios: {0}" -f $script:RunPath) -ForegroundColor Green
if ($script:Issues.Count -gt 0) { Write-Warning 'Existem ocorrencias; revise os avisos no console antes de usar os resultados.' }

