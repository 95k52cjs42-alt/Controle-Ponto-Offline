from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from collections import defaultdict
from functools import wraps
import io
import os

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

# Bibliotecas para o PDF (ReportLab)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "chave_secreta_super_segura_ponto_web")

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DO BANCO DE DADOS
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///ponto.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

CARGA_HORARIA_DIARIA = timedelta(hours=8)


# ==========================================
#         MODELOS DO BANCO DE DADOS
# ==========================================
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    pontos = db.relationship("RegistroPonto", backref="usuario", lazy=True)
    solicitacoes = db.relationship("SolicitacaoCorrecao", backref="usuario", lazy=True)


class RegistroPonto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10), nullable=False)  # DD/MM/YYYY
    tipo = db.Column(db.String(20), nullable=False)
    hora = db.Column(db.String(8), nullable=False)   # HH:MM:SS
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)


class SolicitacaoCorrecao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_ponto = db.Column(db.String(10), nullable=False)  # DD/MM/YYYY
    tipo_ponto = db.Column(db.String(20), nullable=False) # Entrada, Almoço, Retorno, Saída
    hora_correta = db.Column(db.String(8), nullable=False) # HH:MM:SS
    justificativa = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pendente") # Pendente, Aprovada, Recusada
    data_solicitacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acesso permitido apenas para administradores.")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


# Auto-migração e inicialização do banco
with app.app_context():
    db.create_all()
    try:
        from sqlalchemy import text
        db.session.execute(text("ALTER TABLE usuario ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;"))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erro na migração: {e}")


# ==========================================
# ROTAS DE AUTENTICAÇÃO
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "")
        user = Usuario.query.filter_by(email=email).first()

        if user and check_password_hash(user.senha_hash, senha):
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("E-mail ou senha incorretos. Tente novamente.")

    return render_template("login.html")


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "")

        if Usuario.query.filter_by(email=email).first():
            flash("Este e-mail já está cadastrado.")
            return redirect(url_for("cadastro"))

        novo_usuario = Usuario(
            nome=nome,
            email=email,
            senha_hash=generate_password_hash(senha, method="scrypt"),
        )
        db.session.add(novo_usuario)
        db.session.commit()

        flash("Conta criada com sucesso! Faça seu login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da conta.")
    return redirect(url_for("login"))


# ==========================================
# ROTAS DO FUNCIONÁRIO (HISTÓRICO PRÓPRIO)
# ==========================================
@app.route("/meu-historico")
@login_required
def meu_historico():
    data_inicio = request.args.get("data_inicio", "").strip()
    data_fim = request.args.get("data_fim", "").strip()
    tipo_ponto = request.args.get("tipo_ponto", "").strip()

    query = RegistroPonto.query.filter_by(usuario_id=current_user.id)

    # Filtro por Tipo de Ponto
    if tipo_ponto:
        query = query.filter_by(tipo=tipo_ponto)

    registros = query.order_by(RegistroPonto.id.desc()).all()

    # Filtro por Intervalo de Datas no Python (formato DD/MM/YYYY)
    if data_inicio or data_fim:
        registros_filtrados = []
        d_inicio = datetime.strptime(data_inicio, "%Y-%m-%d").date() if data_inicio else None
        d_fim = datetime.strptime(data_fim, "%Y-%m-%d").date() if data_fim else None

        for r in registros:
            try:
                data_reg = datetime.strptime(r.data, "%d/%m/%Y").date()
                if d_inicio and data_reg < d_inicio:
                    continue
                if d_fim and data_reg > d_fim:
                    continue
                registros_filtrados.append(r)
            except ValueError:
                registros_filtrados.append(r)
        registros = registros_filtrados

    return render_template(
        "meu_historico.html",
        registros=registros,
        data_inicio=data_inicio,
        data_fim=data_fim,
        tipo_ponto=tipo_ponto,
    )
# ==========================================
#               ROTAS DO PONTO
# ==========================================
@app.route("/")
@login_required
def index():
    data_hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).strftime("%d/%m/%Y")

    pontos_hoje_objs = RegistroPonto.query.filter_by(
        usuario_id=current_user.id, data=data_hoje
    ).all()
    pontos_batidos = [p.tipo for p in pontos_hoje_objs]

    ultimo_ponto_obj = (
        RegistroPonto.query.filter_by(usuario_id=current_user.id)
        .order_by(RegistroPonto.id.desc())
        .first()
    )

    if ultimo_ponto_obj:
        ultimo_ponto = f"{ultimo_ponto_obj.tipo} às {ultimo_ponto_obj.hora} ({ultimo_ponto_obj.data})"
    else:
        ultimo_ponto = "Nenhum ponto registrado ainda"

    return render_template(
        "index.html", pontos_batidos=pontos_batidos, ultimo_ponto=ultimo_ponto
    )


@app.route("/registrar/<tipo>", methods=["POST"])
@login_required
def registrar(tipo):
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    data_atual = agora.strftime("%d/%m/%Y")
    hora_atual = agora.strftime("%H:%M:%S")

    novo_ponto = RegistroPonto(
        data=data_atual,
        tipo=tipo,
        hora=hora_atual,
        usuario_id=current_user.id,
    )
    db.session.add(novo_ponto)
    db.session.commit()

    flash(f"Ponto ({tipo}) registrado às {hora_atual} com sucesso!")
    return redirect(url_for("index"))


# ==========================================
# ROTAS DE SOLICITAÇÃO DE CORREÇÃO (FUNCIONÁRIO)
# ==========================================
@app.route("/solicitar-correcao", methods=["GET", "POST"])
@login_required
def solicitar_correcao():
    if request.method == "POST":
        data_raw = request.form.get("data_ponto")  # Formato YYYY-MM-DD
        tipo_ponto = request.form.get("tipo_ponto")
        hora = request.form.get("hora_correta")    # Formato HH:MM
        justificativa = request.form.get("justificativa", "").strip()

        if not data_raw or not tipo_ponto or not hora or not justificativa:
            flash("Preencha todos os campos para solicitar a correção.")
            return redirect(url_for("solicitar_correcao"))

        # Formata data para DD/MM/YYYY
        data_obj = datetime.strptime(data_raw, "%Y-%m-%d")
        data_formatada = data_obj.strftime("%d/%m/%Y")
        
        # Garante segundos no horário (HH:MM:SS)
        if len(hora) == 5:
            hora += ":00"

        solicitacao = SolicitacaoCorrecao(
            data_ponto=data_formatada,
            tipo_ponto=tipo_ponto,
            hora_correta=hora,
            justificativa=justificativa,
            usuario_id=current_user.id
        )
        db.session.add(solicitacao)
        db.session.commit()

        flash("Solicitação de correção enviada com sucesso ao Administrador!")
        return redirect(url_for("solicitar_correcao"))

    minhas_solicitacoes = SolicitacaoCorrecao.query.filter_by(
        usuario_id=current_user.id
    ).order_by(SolicitacaoCorrecao.id.desc()).all()

    return render_template("solicitar_correcao.html", solicitacoes=minhas_solicitacoes)


@app.route("/exportar-pdf")
@login_required
def exportar_pdf():
    registros = (
        RegistroPonto.query.filter_by(usuario_id=current_user.id)
        .order_by(RegistroPonto.id.asc())
        .all()
    )

    if not registros:
        flash("Nenhum registro encontrado para exportar em PDF.")
        return redirect(url_for("index"))

    dias = defaultdict(dict)
    for r in registros:
        dias[r.data][r.tipo] = r.hora

    tabela_linhas = [["Dia", "Entrada", "Almoço", "Retorno", "Saída", "Total Horas"]]
    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    FMT = "%H:%M:%S"

    for dia, reg in dias.items():
        e = reg.get("Entrada", "--:--")
        a = reg.get("Almoço", "--:--")
        r = reg.get("Retorno", "--:--")
        s = reg.get("Saída", "--:--")

        tempo_trabalhado = timedelta()

        if e != "--:--" and a != "--:--":
            t1, t2 = datetime.strptime(e, FMT), datetime.strptime(a, FMT)
            if t2 > t1:
                tempo_trabalhado += t2 - t1

        if r != "--:--" and s != "--:--":
            t3, t4 = datetime.strptime(r, FMT), datetime.strptime(s, FMT)
            if t4 > t3:
                tempo_trabalhado += t4 - t3

        tot = int(tempo_trabalhado.total_seconds())
        total_segundos_trabalhados += tot

        if tempo_trabalhado > CARGA_HORARIA_DIARIA:
            extra = tempo_trabalhado - CARGA_HORARIA_DIARIA
            total_segundos_extras += int(extra.total_seconds())

        hrs, mins = divmod(tot // 60, 60)
        tabela_linhas.append([dia, e, a, r, s, f"{hrs:02d}:{mins:02d}h"])

    hrs_t, mins_t = divmod(total_segundos_trabalhados // 60, 60)
    hrs_e, mins_e = divmod(total_segundos_extras // 60, 60)

    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30,
    )
    elementos = []
    estilos = getSampleStyleSheet()

    titulo_estilo = ParagraphStyle(
        "T", parent=estilos["Heading1"], fontSize=18, alignment=1, spaceAfter=15
    )
    elementos.append(
        Paragraph(f"<b>Folha de Ponto - {current_user.nome}</b>", titulo_estilo)
    )
    elementos.append(
        Paragraph(
            f"<b>E-mail:</b> {current_user.email} | <b>Emissão:</b>"
            f" {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y às %H:%M')}",
            estilos["Normal"],
        )
    )
    elementos.append(Spacer(1, 15))

    tabela = Table(tabela_linhas, colWidths=[80, 85, 85, 85, 85, 90])
    tabela.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f8f9fa")],
            ),
        ])
    )
    elementos.append(tabela)
    elementos.append(Spacer(1, 20))

    dados_resumo = [
        ["Horas Totais Trabalhadas:", f"{hrs_t:02d}:{mins_t:02d}h"],
        [
            "Total de Horas Extras (Excedente 8h/dia):",
            f"{hrs_e:02d}:{mins_e:02d}h",
        ],
    ]
    tabela_resumo = Table(dados_resumo, colWidths=[300, 210])
    tabela_resumo.setStyle(
        TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#2e7d32")),
        ])
    )
    elementos.append(tabela_resumo)

    pdf.build(elementos)
    buffer.seek(0)

    agora_br = datetime.now(ZoneInfo("America/Sao_Paulo"))
    nome_arquivo_pdf = (
        f"Folha_Ponto_{current_user.nome.replace(' ', '_')}_{agora_br.strftime('%m_%Y')}.pdf"
    )

    return send_file(
        buffer,
        as_attachment=True,
        download_name=nome_arquivo_pdf,
        mimetype="application/pdf",
    )


# ==========================================
#          ROTAS DE ADMINISTRAÇÃO
# ==========================================
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    usuarios = Usuario.query.all()
    solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    return render_template("admin.html", usuarios=usuarios, solicitacoes_pendentes=solicitacoes_pendentes)


@app.route("/admin/historico")
@login_required
@admin_required
def admin_historico():
    usuario_id = request.args.get("usuario_id", type=int)
    busca_nome = request.args.get("busca_nome", "").strip()
    data_inicio = request.args.get("data_inicio", "").strip()
    data_fim = request.args.get("data_fim", "").strip()
    tipo_ponto = request.args.get("tipo_ponto", "").strip()

    query = RegistroPonto.query.join(Usuario)

    # Filtro por Funcionário via Select
    if usuario_id:
        query = query.filter(RegistroPonto.usuario_id == usuario_id)

    # Filtro por Nome ou E-mail
    if busca_nome:
        query = query.filter(
            (Usuario.nome.ilike(f"%{busca_nome}%")) | (Usuario.email.ilike(f"%{busca_nome}%"))
        )

    # Filtro por Tipo de Ponto
    if tipo_ponto:
        query = query.filter(RegistroPonto.tipo == tipo_ponto)

    registros = query.order_by(RegistroPonto.id.desc()).all()

    # Filtro por Intervalo de Datas no Python (formato DD/MM/YYYY)
    if data_inicio or data_fim:
        registros_filtrados = []
        d_inicio = datetime.strptime(data_inicio, "%Y-%m-%d").date() if data_inicio else None
        d_fim = datetime.strptime(data_fim, "%Y-%m-%d").date() if data_fim else None

        for r in registros:
            try:
                data_reg = datetime.strptime(r.data, "%d/%m/%Y").date()
                if d_inicio and data_reg < d_inicio:
                    continue
                if d_fim and data_reg > d_fim:
                    continue
                registros_filtrados.append(r)
            except ValueError:
                registros_filtrados.append(r)
        registros = registros_filtrados

    usuarios = Usuario.query.order_by(Usuario.nome.asc()).all()

    return render_template(
        "admin_historico.html",
        registros=registros,
        usuarios=usuarios,
        usuario_id_selecionado=usuario_id,
        busca_nome=busca_nome,
        data_inicio=data_inicio,
        data_fim=data_fim,
        tipo_ponto=tipo_ponto,
    )

@app.route("/admin/solicitacoes")
@login_required
@admin_required
def admin_solicitacoes():
    solicitacoes = SolicitacaoCorrecao.query.order_by(SolicitacaoCorrecao.id.desc()).all()
    return render_template("admin_solicitacoes.html", solicitacoes=solicitacoes)


@app.route("/admin/solicitacoes/<int:id>/<acao>", methods=["POST"])
@login_required
@admin_required
def responder_solicitacao(id, acao):
    solicitacao = SolicitacaoCorrecao.query.get_or_404(id)

    if acao == "aprovar":
        solicitacao.status = "Aprovada"
        
        # Verifica se já existe um registro do mesmo tipo nessa data para o usuário
        ponto_existente = RegistroPonto.query.filter_by(
            usuario_id=solicitacao.usuario_id,
            data=solicitacao.data_ponto,
            tipo=solicitacao.tipo_ponto
        ).first()

        if ponto_existente:
            ponto_existente.hora = solicitacao.hora_correta
        else:
            novo_ponto = RegistroPonto(
                data=solicitacao.data_ponto,
                tipo=solicitacao.tipo_ponto,
                hora=solicitacao.hora_correta,
                usuario_id=solicitacao.usuario_id
            )
            db.session.add(novo_ponto)

        flash("Solicitação APROVADA e histórico de ponto atualizado!")

    elif acao == "recusar":
        solicitacao.status = "Recusada"
        flash("Solicitação RECUSADA com sucesso.")

    db.session.commit()
    return redirect(url_for("admin_solicitacoes"))


@app.route("/admin/toggle-admin/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_admin(user_id):
    if user_id == current_user.id:
        flash("Você não pode alterar o seu próprio status de administrador.")
        return redirect(url_for("admin_panel"))

    usuario = Usuario.query.get_or_404(user_id)
    usuario.is_admin = not usuario.is_admin
    db.session.commit()

    status = "promovido a" if usuario.is_admin else "removido de"
    flash(f"Usuário {usuario.nome} foi {status} Administrador com sucesso!")
    return redirect(url_for("admin_panel"))


if __name__ == "__main__":
    app.run(debug=True)