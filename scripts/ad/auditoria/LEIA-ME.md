# Auditoria de grupos administrativos do AD

O `Audit-ADAdmins.ps1` consulta o AD sem alterar contas ou permissoes e gera **somente dois arquivos por execucao**, em uma subpasta exclusiva:

- `01-Usuarios.csv`
- `02-GruposAdministrativos.csv`

Arquivos de execucoes anteriores nao sao apagados. Nao e necessario Excel instalado.

## Execucao

Requer Windows Server 2012 ou posterior, Windows PowerShell 3.0+ (`powershell.exe`) e o modulo `ActiveDirectory` do RSAT. A identidade Windows atual deve ter acesso de leitura ao AD e aos DCs consultados.

```powershell
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -ExactLastLogon

# Restringir o inventario a um dominio:
.\Audit-ADAdmins.ps1 -Server dc01.empresa.local -Domains empresa.local -OutputPath C:\AuditoriaAD -ExactLastLogon

# Pular a analise complementar de ACLs:
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -ExactLastLogon -SkipAclScan
```

Por padrao, inventaria todos os dominios da floresta. `-Server` orienta a descoberta inicial; cada dominio e inventariado no seu PDC Emulator. Caso precise instalar o modulo, um administrador pode executar `Install-WindowsFeature RSAT-AD-PowerShell` no servidor.

## 01-Usuarios.csv

Contem exatamente estas colunas:

`Usuario;Estado;Grupos que concedem privilégios;Como o usuário recebe o privilégio;Ultima troca de senha;Último logon registrado`

Inclui apenas usuarios com associacao direta ou indireta a grupos privilegiados conhecidos. O script primeiro cruza todos os vinculos e so depois filtra a exportacao. Assim, um usuario do grupo `grp-admin-ti`, que pertence a `Administradores`, aparece no CSV mesmo sem associacao direta a `Administradores`.

- `Usuario`: login (`sAMAccountName`).
- `Estado`: Habilitado ou Desabilitado. Contas habilitadas e desabilitadas com associacao privilegiada sao exportadas por padrao.
- `Grupos que concedem privilégios`: papeis privilegiados encontrados, separados por ` | `.
- `Como o usuário recebe o privilégio`: somente nomes, como `grp-admin-ti > Administrators`. Caminhos alternativos sao mantidos e separados por ` | `.
- `Ultima troca de senha` e `Último logon registrado`: `dd/MM/yyyy HH:mm`, no horario de Brasilia.

Usuarios comuns e usuarios ligados apenas a grupos de distribuicao nao sao exportados. O grupo primario tambem entra no cruzamento.

## 02-GruposAdministrativos.csv

Contem exatamente estas colunas:

`Grupo;Contas e grupos incluídos diretamente;Este grupo está incluído em;Total de membros diretos`

Inclui os grupos privilegiados conhecidos e os grupos de seguranca encontrados nos seus aninhamentos, inclusive grupos relevantes vazios.

- `Grupo`: nome do grupo.
- `Contas e grupos incluídos diretamente`: login dos usuarios ou nome dos grupos, separados por ` | `, sem dominio e sem `[member]` ou `[primaryGroupID]`.
- `Este grupo está incluído em`: nomes dos grupos pais, sem dominio.
- `Total de membros diretos`: total dos vinculos diretos, incluindo grupo primario e objetos que nao sao expandidos como usuarios, como computadores.

Os membros diretos de um grupo sao preservados, inclusive objetos que nao participam da expansao administrativa. Computadores aparecem pelo `sAMAccountName` quando disponivel. Referencias que nao puderem ser resolvidas aparecem como `Membro nao resolvido`, com detalhes no console.

## Criterio administrativo e ACLs

Os grupos padrao sao reconhecidos por SID, mesmo renomeados ou em outro idioma: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, Key Admins e Enterprise Key Admins. Esses grupos possuem capacidades diferentes; participar deles nao equivale sempre a ser Domain Admin. DnsAdmins e reconhecido por `sAMAccountName`.

Grupos personalizados dentro desses grupos sao incluidos normalmente, junto com seus usuarios. Os vinculos internos continuam usando DN e SID; a retirada do dominio e apenas visual. Em florestas com nomes repetidos, as linhas podem ter nomes iguais, embora as identidades sejam distintas.

A analise complementar de ACLs continua verificando permissoes de escrita, controle, direitos estendidos e propriedade dos objetos nas particoes anunciadas pelos DCs selecionados. **Uma ACL isolada nao inclui automaticamente o principal ou seus membros nos CSVs.** Isso evita classificar como administrador um usuario comum com uma delegacao limitada, como editar um atributo. Candidatos fora do filtro administrativo sao informados no console para revisao no AD. Nao ha mais arquivo de ACLs. Use `-SkipAclScan` para pular essa analise complementar.

O filtro dos dois CSVs e, portanto, associacao aos grupos privilegiados conhecidos, direta ou por aninhamento. Administracao delegada exclusivamente por ACL, sem esse vinculo, requer revisao separada e nao e apresentada como administracao confirmada. Nao ha calculo de acesso efetivo com combinacao de Allow/Deny, restricoes de heranca ou token.

## Datas, logon e formato

Datas usam o fuso Windows `E. South America Standard Time`, correspondente a Brasilia, independentemente do fuso configurado no servidor executor. A conversao respeita as regras historicas disponiveis no Windows. Exemplo: `24/09/2026 01:30:00 UTC` vira `23/09/2026 22:30`.

Sem `-ExactLastLogon`, o script usa `lastLogonTimestamp`, um valor replicado e aproximado. Com a opcao, consulta os DCs atuais de cada dominio e usa o maior `lastLogon`. Se um DC falhar, o console informa que o resultado e parcial; o CSV conserva a maior data obtida, sem coluna adicional. `Nao registrado` indica atributo ausente/zero, nao prova que a conta nunca foi usada. DCs desativados e historico de sessoes interativas nao sao reconstruidos.

Os CSVs usam ponto e virgula e UTF-8 com BOM. Use `-Delimiter ','` para alterar o separador. Textos com prefixos de formulas sao protegidos com apostrofo. Se o Excel nao identificar o formato automaticamente, importe por Dados > De Texto/CSV. Celulas agregadas muito grandes estao sujeitas aos limites de exibicao do Excel.

## Avisos e limites

Falhas de leitura, membros nao expandidos, ciclos e limites de busca aparecem **somente no console**, sem criar arquivos auxiliares. Revise esses avisos: uma coleta parcial pode omitir administradores. A ausencia de um usuario no CSV nao garante ausencia de privilegios fora do escopo ou em objetos que a conta coletora nao consiga enxergar.

`-MaxDepth 100` e `-MaxPathsPerRoot 100000` sao os limites padrao de profundidade e de estados percorridos por origem. Atingir um limite gera aviso e resultados parciais. O script preserva caminhos alternativos e interrompe ciclos sem entrar em loop.

A coleta nao cobre administradores locais de servidores/estacoes, aplicacao de GPO/GPP, SYSVOL, SIDHistory, AD CS, nuvem ou expansao de trusts externos. Foreign Security Principals sao associados por SID quando a identidade correspondente esta no inventario. Computadores e contas gerenciadas de servico nao sao expandidos como usuarios. A coleta e sequencial e nao representa uma fotografia transacional do AD.

## Testes

```powershell
.\Tests\Test-AuditAD.ps1
```

Os testes offline usam cmdlets simulados e verificam filtro administrativo, caminhos indiretos e alternativos, grupo primario, ciclos, nomes sem dominio, uso do login, conversao para Brasilia, colunas e quantidade de arquivos. Nao substituem validacao em um AD real ou em Windows Server 2012.

No CSV 01, os grupos privilegiados padrao aparecem em ingles, inclusive nos caminhos; grupos personalizados mantem seus nomes. No CSV 02, os nomes originais do AD sao preservados, conforme o modelo. Os cabecalhos e estados permanecem em portugues, como nos prints. Group Policy Creator Owners nao e considerado uma origem de privilegio: membros exclusivos desse grupo nao entram no CSV 01. No CSV 02, ele pode aparecer como grupo pai de outro grupo, preservando a associacao real mostrada no print. Nenhuma coluna de detalhes de leitura de permissoes e exportada. Usuarios habilitados e desabilitados sao incluidos por padrao. Datas em Brasilia, sem segundos. O CSV 01 e ordenado por privilegios e usuario; o CSV 02, por grupo.

