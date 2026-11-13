# Prepara um PC Windows para trabalhar neste projeto: programas, extensões do
# VS Code, Claude Code e o ambiente Python (requirements_new.txt).
#
# Como usar (PowerShell, na pasta do projeto já clonada do GitHub):
#   powershell -ExecutionPolicy Bypass -File .\instalar_em_casa.ps1
#
# O que fica de fora de propósito: o arquivo .env (tem senhas e chaves; copie
# do PC do trabalho por um meio seguro, nunca pelo git) e os logins
# (heroku login / claude), que você faz no final.

$ErrorActionPreference = "Stop"
function Passo($texto) { Write-Host "`n==> $texto" -ForegroundColor Cyan }
function Tem($comando) { [bool](Get-Command $comando -ErrorAction SilentlyContinue) }
function AtualizarPath {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}

# ---------------------------------------------------------------------------
# 1. Programas (winget, já vem no Windows 10/11)
# ---------------------------------------------------------------------------
$programas = @(
    @{ Comando = "python";  Id = "Python.Python.3.14";        Nome = "Python 3.14" },
    @{ Comando = "git";     Id = "Git.Git";                   Nome = "Git" },
    @{ Comando = "node";    Id = "OpenJS.NodeJS.LTS";         Nome = "Node.js" },
    @{ Comando = "code";    Id = "Microsoft.VisualStudioCode"; Nome = "VS Code" },
    @{ Comando = "heroku";  Id = "Heroku.HerokuCLI";          Nome = "Heroku CLI" }
)
foreach ($p in $programas) {
    Passo "Verificando $($p.Nome)"
    if (Tem $p.Comando) { Write-Host "    já instalado" ; continue }
    winget install --id $p.Id -e --accept-source-agreements --accept-package-agreements
    AtualizarPath
}

# ---------------------------------------------------------------------------
# 2. Claude Code (linha de comando)
# ---------------------------------------------------------------------------
Passo "Claude Code"
if (Tem "claude") {
    Write-Host "    já instalado: $(claude --version)"
} else {
    npm install -g @anthropic-ai/claude-code
    AtualizarPath
}

# ---------------------------------------------------------------------------
# 3. Extensões do VS Code (as mesmas do PC do trabalho)
# ---------------------------------------------------------------------------
$extensoes = @(
    "anthropic.claude-code",
    "diegosouzapw.omnicopilot",
    "mechatroner.rainbow-csv",
    "ms-azuretools.vscode-containers",
    "ms-python.debugpy",
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.vscode-python-envs",
    "ms-vscode-remote.remote-containers",
    "ms-vscode.powershell",
    "natizyskunk.sftp",
    "saoudrizwan.claude-dev",
    "tomoki1207.pdf"
)
Passo "Extensões do VS Code"
foreach ($ext in $extensoes) {
    code --install-extension $ext --force | Out-Null
    Write-Host "    $ext"
}

# ---------------------------------------------------------------------------
# 4. Ambiente Python do projeto
# ---------------------------------------------------------------------------
Passo "Ambiente Python (.venv + requirements_new.txt)"
if (-not (Test-Path ".venv\Scripts\python.exe")) { python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements_new.txt

# ---------------------------------------------------------------------------
# 5. O que falta fazer à mão
# ---------------------------------------------------------------------------
Passo "Pronto. Falta só:"
Write-Host @"
    1. Copiar o arquivo .env do PC do trabalho para esta pasta (por pendrive,
       gerenciador de senhas etc.; NUNCA pelo git).
    2. heroku login      (abre o navegador)
    3. claude            (na primeira vez pede o login da sua conta)
    4. Testar:  .\.venv\Scripts\python.exe app.py   ->  http://localhost:1234
    5. Rodar os testes:  .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
"@
