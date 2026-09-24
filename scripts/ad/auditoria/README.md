# Auditoria de grupos administrativos do Active Directory

Script PowerShell de **somente leitura** para identificar contas associadas a grupos privilegiados do AD, diretamente ou por grupos aninhados. Exporta dois CSVs que podem ser abertos no Excel.

## Uso rápido

1. Baixe este repositório em **Code > Download ZIP** e extraia os arquivos.
2. Abra o **Windows PowerShell** na pasta extraída.
3. Execute:

```powershell
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -ExactLastLogon
```

Os resultados ficam em uma subpasta de `C:\AuditoriaAD`, identificada pela execução. O script não altera contas, grupos ou permissões.

### Requisitos

- Windows Server 2012 ou posterior e Windows PowerShell 3.0+ (`powershell.exe`).
- Módulo `ActiveDirectory` das ferramentas RSAT.
- Conta com leitura dos objetos e permissões auditados, além de conectividade com os controladores de domínio.

Se o módulo não estiver instalado, um administrador pode instalar o recurso no Windows Server:

```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

Caso a política de execução bloqueie o script, siga o procedimento de aprovação ou assinatura da sua organização.

## Resultados

| Arquivo | Conteúdo |
|---|---|
| `01-Usuarios.csv` | Usuário, estado, grupos que concedem privilégios, caminhos dos grupos, última troca de senha e último logon registrado. |
| `02-GruposAdministrativos.csv` | Grupo, contas e grupos incluídos diretamente, grupos pais e total de membros diretos. |

- Contas habilitadas **e desabilitadas** são incluídas quando pertencem a grupos privilegiados.
- `TI > Domain Admins` significa que TI está incluído em Domain Admins. ` | ` separa resultados diferentes.
- No CSV de usuários, os grupos padrão aparecem em inglês; no de grupos, os nomes originais do AD são preservados.
- Datas em Brasília, no formato `dd/MM/yyyy HH:mm`, sem segundos.
- CSVs em UTF-8 com BOM, separados por ponto e vírgula. Cores, filtros e larguras de coluna são configurados no Excel.

## Outras formas de executar

```powershell
# Inventariar um domínio específico:
.\Audit-ADAdmins.ps1 -Domains empresa.local -OutputPath C:\AuditoriaAD -ExactLastLogon

# Pular a análise complementar de ACLs e manter a análise de grupos:
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -ExactLastLogon -SkipAclScan

# Exportar somente contas habilitadas:
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -IncludeDisabled:$false
```

Sem `-Domains`, o script inventaria os domínios da floresta. Sem `-ExactLastLogon`, usa a data aproximada de `lastLogonTimestamp`.

## Como interpretar

O relatório identifica **associação a grupos privilegiados**, não comprova que todas as contas sejam administradoras totais do domínio. Print Operators, por exemplo, tem uma função diferente de Domain Admins.

Group Policy Creator Owners não é tratado como origem de privilégio nesta versão. Delegações encontradas nas ACLs geram avisos para revisão, mas não incluem automaticamente contas nos CSVs. Administradores locais, SIDHistory, políticas aplicadas por GPO e privilégios fora do AD não são cobertos.

**Leia os avisos no console.** Se um controlador não responder à consulta de logon, as datas serão parciais. “Nao registrado” não significa que a conta nunca foi usada. Antes de remover acessos com base nos relatórios, valide a necessidade da conta e o impacto da alteração.

Veja [LEIA-ME.md](LEIA-ME.md) para os detalhes de escopo e limitações.

## Testes

```powershell
.\Tests\Test-AuditAD.ps1
```

Os testes usam dados fictícios e não consultam o AD. A compatibilidade com Windows PowerShell 3.0 foi considerada na implementação; os testes offline não substituem validação na versão do Windows e no ambiente de destino.

## Evolução

Este é um script independente, destinado a uma futura coleção de ferramentas de administração. A central com menus e a distribuição pela PowerShell Gallery ficam para uma etapa posterior.
