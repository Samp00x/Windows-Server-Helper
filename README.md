# Windows Server Helper

Coleção de scripts PowerShell para administração e auditoria de ambientes Windows Server.

## Scripts disponíveis

| Categoria | Script | Função |
|---|---|---|
| Active Directory / Auditoria | [Auditoria de grupos administrativos](scripts/ad/auditoria/README.md) | Identifica usuários associados a grupos privilegiados, incluindo aninhamentos, e gera dois CSVs. |

## Começar

Baixe o repositório em **Code > Download ZIP**, extraia os arquivos e abra o Windows PowerShell na pasta do repositório.

```powershell
cd .\scripts\ad\auditoria
.\Audit-ADAdmins.ps1 -OutputPath C:\AuditoriaAD -ExactLastLogon
```

O primeiro script requer Windows PowerShell 3.0+ e o módulo `ActiveDirectory` (RSAT). Consulte o [guia rápido](scripts/ad/auditoria/README.md) antes de executar.

## Organização

```text
scripts/
└── ad/
    └── auditoria/
        ├── Audit-ADAdmins.ps1
        ├── README.md
        ├── LEIA-ME.md
        └── Tests/
            └── Test-AuditAD.ps1
```

Cada área mantém seus scripts, instruções e testes. Dependências externas são descritas no manual de cada script; não são instaladas automaticamente.

## Desenvolvimento

Os testes da auditoria de AD usam dados fictícios e não consultam o diretório:

```powershell
.\scripts\ad\auditoria\Tests\Test-AuditAD.ps1
```

Não inclua relatórios de clientes, credenciais ou dados reais em commits e issues.

## Próximas etapas

A coleção poderá receber scripts de outras áreas, como File Server. A central interativa com menus e a distribuição pela PowerShell Gallery serão desenvolvidas posteriormente. Nesta versão, os scripts são executados individualmente.
