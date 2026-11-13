# 4Lab Orbit: Controle de Ponto

Sistema de ponto eletrônico (CLT, Portaria 671) de uma empresa só. Flask monolítico,
em português (código, mensagens, commits e conversa com o usuário).

## Stack e infraestrutura
- `app.py` (~6.000 linhas) concentra modelos, rotas e regras. Templates Jinja em `templates/`
  (`admin.html` é o shell do painel; as abas são `admin_fragment_*.html`, carregadas por fetch).
- Banco: **Postgres no Supabase** (pooler, porta 6543). O `.env` local aponta para o banco de
  PRODUÇÃO: cuidado com escritas no localhost.
- Hospedagem: **Heroku**, app `pontoweb` (https://pontoweb-fdf42f1dbd77.herokuapp.com).
  **Push na `main` do GitHub faz deploy automático**; a fase `release` roda `flask --app app init-db`.
  Disco efêmero. Fly.io foi abandonado.
- Migrações: não há Alembic. Coluna nova = `ALTER TABLE` idempotente em
  `_apply_database_migrations()` + campo no modelo; tabela nova sai do `db.create_all()`.
  Ao mudar o modelo, o banco precisa do `init-db` antes de o código novo rodar.
- Heroku CLI no Windows corta valores de config com hífen: gravar config vars pela API
  (`PATCH https://api.heroku.com/apps/pontoweb/config-vars` com o token de `heroku auth:token`).
- Rodar: `.venv\Scripts\python.exe app.py` (http://localhost:1234). Testes (SQLite temporário,
  não tocam no Supabase): `.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"`.
  Rodar a suíte inteira antes de cada commit; para JS de template, checar sintaxe com `node --check`.

## Papéis e regras de negócio (decididas pelo usuário)
- Papéis acumuláveis: **RH** (pessoas, ponto, correções, relatórios, fechamento) e **TI**
  (parâmetros, setores, feriados, acessos, logs, quiosque). Sem papel = colaborador.
- Separação de funções: ninguém se dá papel/isenção; ninguém mexe no próprio ponto
  (lançar, excluir, aprovar correção, afastamento); RH não exclui contas RH/TI.
- Senhas: cada um troca a própria no perfil; RH troca a de colaboradores e do RH, nunca da TI;
  TI troca a de todos; emergência: `heroku run flask --app app redefinir-senha --email ...`.
- **Superadmin** (`SUPERADMIN_EMAILS`, hoje `admin@ponto.com`): acima dessas regras; cada uso
  vai para o log com `[ADMIN]`. `AUTOAPROVACAO_EMAILS` libera aprovar a própria solicitação
  (`[AUTOAPROVAÇÃO]`). Essas listas ficam só no ambiente do servidor, nunca na tela.
- "Esqueci minha senha" desligado (`ESQUECI_SENHA_ATIVO`) até o Resend ter domínio verificado.
- Raio do local de trabalho (Parâmetros > Local de trabalho): batida pelo app só dentro do raio;
  botão trava fora dele; isenção por usuário (`ponto_fora_do_raio`, aba Acessos).
- Horas extras são pagas (sem banco de horas). Fotos do quiosque guardadas 5 anos.

## Quiosque (`/quiosque`)
- Tablet autorizado pela TI (Parâmetros > Quiosque > "Ativar este aparelho"): token opaco em
  cookie de 400 dias renovado a cada uso (`QuiosqueDispositivo`, só o hash). Um ativo por vez.
  Saída escondida: segurar o canto superior direito 5 s + conta TI.
- Método (Parâmetros > Quiosque): CPF/e-mail ou reconhecimento facial.
  CPF/e-mail: detecção de rosto com MediaPipe (`static/quiosque/mediapipe`).
  Facial: só a face-api (`static/quiosque/faceapi`), descritor de 128 números; servidor compara
  (limiar 0,50, folga 0,06). Rostos cadastrados pela TI (Configurar > Rosto, com consentimento LGPD).
- Arquivos de `/static/quiosque/` têm cache de 30 dias (immutable): ao atualizar, trocar o nome.
- Foco atual: estabilidade/velocidade do reconhecimento no iPhone (preparo e aquecimento na tela
  inicial, tempos-limite, a tela inicial mostra "pronto (placa de vídeo/processador, N s)").

## Segurança e convenções do front-end (não quebrar)
- CSP sem `'unsafe-inline'` em scripts: todo `<script>` inline leva `nonce="{{ csp_nonce() }}"`;
  **nada de `onclick`/`onsubmit` em HTML** (use `data-*` + listener). Confirmações:
  `data-confirm="..."` no `<form>`. Scripts de CDN: só os de `_CDN_SCRIPTS`, com `integrity`.
- Scripts dentro de fragmentos de aba NÃO executam (innerHTML): a lógica fica no `admin.html`
  por delegação de eventos. Filtros de aba: `<form data-filtro-view="...">` (ver Logs).
- Câmera liberada só em `/quiosque` e no painel para TI; `'wasm-unsafe-eval'` só no quiosque.
- CSRF em todo POST (form `_csrf_token` ou header `X-CSRF-Token`).
- Toda ação sensível chama `registrar_log(...)` (texto até 200 caracteres; CPF mascarado).
- Commits pequenos, mensagem em português explicando o porquê, com
  `Co-Authored-By: Claude <noreply@anthropic.com>`. Push só quando o usuário pedir
  (o push publica em produção). Não rodar `init-db` no banco sem o usuário autorizar.

## Pendências conhecidas
- E-mail (Resend com domínio da empresa) para reativar "Esqueci minha senha".
- Exclusão de usuário apaga os pontos: trocar por desativação (Portaria 671 exige guarda).
- Espaço das fotos no Supabase (~5 GB em 5 anos para 30 pessoas): plano ou Supabase Storage.
- Push no Brave: exige ativar "serviços do Google para mensagens push" no navegador.
