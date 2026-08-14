import io
import os
from collections import defaultdict
from datetime import datetime, timedelta, date
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
    redirect,
    make_response,
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

# Bibliotecas para a geração do PDF (ReportLab)
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


# Função auxiliar para verificar se a data cai em dia útil (Segunda a Sexta)
def eh_dia_util(data_obj):
    return data_obj.weekday() < 5


# ==========================================
#          MODELOS DO BANCO DE DADOS
# ==========================================
class Notificacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    titulo = db.Column(db.String(150), default="Aviso Geral")
    mensagem = db.Column(db.Text, nullable=False)
    tipo = db.Column(db.String(50), default="info")  # Ex: 'info', 'danger', etc.
    link = db.Column(db.String(255), nullable=True)   # Link opcional para redirecionar
    lida = db.Column(db.Boolean, default=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)

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
    foi_ajustado = db.Column(db.Boolean, default=False)


class SolicitacaoCorrecao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_ponto = db.Column(db.String(10), nullable=False)  # DD/MM/YYYY
    tipo_ponto = db.Column(db.String(20), nullable=False)
    hora_correta = db.Column(db.String(8), nullable=False)
    justificativa = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pendente")
    data_solicitacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acesso permitido apenas para administradores.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


# Auto-migração do banco de dados
with app.app_context():
    db.create_all()
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)

        colunas_usuario = [c["name"] for c in inspector.get_columns("usuario")]
        if "is_admin" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN is_admin BOOLEAN DEFAULT FALSE;"))

        colunas_ponto = [c["name"] for c in inspector.get_columns("registro_ponto")]
        if "foi_ajustado" not in colunas_ponto:
            db.session.execute(text("ALTER TABLE registro_ponto ADD COLUMN foi_ajustado BOOLEAN DEFAULT FALSE;"))

        db.session.commit()
    except Exception as e:
        db.session.rollback()


# ==========================================
#         SISTEMA DE NOTIFICAÇÕES
# ==========================================

# Definimos os 4 pontos obrigatórios da jornada diária
PONTOS_OBRIGATORIOS = ["Entrada", "Almoço", "Retorno", "Saída"]


def identificar_pontos_faltantes(registros_do_dia):
    """Dado uma lista de registros de um único dia,

    retorna uma lista com os tipos de ponto que faltaram bater.
    """
    # p.tipo garante que vai ler o tipo correto do seu model RegistroPonto
    tipos_batidos = [
        getattr(p, "tipo", getattr(p, "tipo_ponto", ""))
        for p in registros_do_dia
    ]
    faltantes = [p for p in PONTOS_OBRIGATORIOS if p not in tipos_batidos]
    return faltantes


def obter_notificacoes_usuario(user_id):
    if not user_id:
        return []

    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    notificacoes = []

    try:
        # Busca todos os pontos do usuário
        registros = RegistroPonto.query.filter_by(usuario_id=user_id).all()

        # Agrupa registros por data e guarda quais datas tiveram ponto
        pontos_por_data = {}
        primeiro_registro_data = hoje

        for r in registros:
            try:
                # Converte string 'DD/MM/AAAA' para objeto date
                d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()

                if d_obj not in pontos_por_data:
                    pontos_por_data[d_obj] = []
                pontos_por_data[d_obj].append(r)

                if d_obj < primeiro_registro_data:
                    primeiro_registro_data = d_obj
            except (ValueError, TypeError):
                pass

        # 1. VERIFICAÇÃO DE DIAS ÚTEIS COM FALTAS TOTAIS
        limite_busca = (
            primeiro_registro_data
            if registros
            else (hoje - timedelta(days=30))
        )
        curr = hoje - timedelta(days=1)
        faltas_count = 0

        while curr >= limite_busca:
            if eh_dia_util(curr) and curr not in pontos_por_data:
                faltas_count += 1
            curr -= timedelta(days=1)

        if faltas_count > 0:
            notificacoes.append({
                "id": "faltas_passadas",
                "tipo": "danger",
                "titulo": "Pontos Pendentes!",
                "mensagem": f"Você possui {faltas_count} dia(s) útil(eis) com registro de ponto ausente.",
                "link": url_for("meu_historico"),
            })

        # 2. VERIFICAÇÃO DE PONTOS INCOMPLETOS EM DIAS ANTERIORES
        dias_incompletos = 0
        for d_obj, regs_do_dia in pontos_por_data.items():
            if d_obj < hoje and eh_dia_util(d_obj):
                faltantes = identificar_pontos_faltantes(regs_do_dia)
                if faltantes:
                    dias_incompletos += 1

        if dias_incompletos > 0:
            notificacoes.append({
                "id": "pontos_incompletos",
                "tipo": "warning",
                "titulo": "Pontos Incompletos!",
                "mensagem": f"Você tem {dias_incompletos} dia(s) com batidas de ponto incompletas.",
                "link": url_for("meu_historico"),
            })

        # 3. VERIFICAÇÃO DO PONTO DE HOJE
        if eh_dia_util(hoje):
            data_hoje_str = hoje.strftime("%d/%m/%Y")
            pontos_hoje = [
                p.tipo
                for p in RegistroPonto.query.filter_by(
                    usuario_id=user_id, data=data_hoje_str
                ).all()
            ]

            if "Entrada" not in pontos_hoje:
                notificacoes.append({
                    "id": "ponto_hoje",
                    "tipo": "warning",
                    "titulo": "Atenção ao Ponto",
                    "mensagem": "Você ainda não registrou o ponto de Entrada hoje!",
                    "link": url_for("index"),
                })

    except Exception as e:
        print(f"Erro ao gerar notificações: {e}")
        return []

    return notificacoes


@app.context_processor
def inject_notifications():
    try:
        if current_user and current_user.is_authenticated:
            notifs = obter_notificacoes_usuario(current_user.id)
            return dict(
                notificacoes_usuario=notifs, total_notificacoes=len(notifs)
            )
    except Exception:
        pass
    return dict(notificacoes_usuario=[], total_notificacoes=0)


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
            flash("E-mail ou senha incorretos.", "danger")

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
            flash("Este e-mail já está cadastrado.", "warning")
            return redirect(url_for("cadastro"))

        is_first = Usuario.query.count() == 0
        novo_usuario = Usuario(
            nome=nome,
            email=email,
            senha_hash=generate_password_hash(senha, method="scrypt"),
            is_admin=is_first
        )
        db.session.add(novo_usuario)
        db.session.commit()

        flash("Conta criada com sucesso! Faça seu login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da conta.", "info")
    return redirect(url_for("login"))


# ==========================================
# ROTAS DO FUNCIONÁRIO & PONTO
# ==========================================
@app.route("/")
@login_required
def index():
    data_hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).strftime("%d/%m/%Y")

    pontos_hoje_objs = RegistroPonto.query.filter_by(
        usuario_id=current_user.id, data=data_hoje
    ).order_by(RegistroPonto.id.asc()).all()
    
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
        "index.html",
        pontos_batidos=pontos_batidos,
        ultimo_ponto=ultimo_ponto,
        data_hoje=data_hoje,
        registros_hoje=pontos_hoje_objs
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
        foi_ajustado=False
    )
    db.session.add(novo_ponto)
    db.session.commit()

    flash(f"Ponto ({tipo}) registrado às {hora_atual} com sucesso!", "success")
    return redirect(url_for("index"))


@app.route("/meu_historico")
@login_required
def meu_historico():
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    registros = (
        RegistroPonto.query.filter_by(usuario_id=current_user.id)
        .order_by(RegistroPonto.id.desc())
        .all()
    )

    dias_registrados = {}
    primeira_data = hoje

    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            if d_obj not in dias_registrados:
                dias_registrados[d_obj] = []
            dias_registrados[d_obj].append(r)
            
            if d_obj < primeira_data:
                primeira_data = d_obj
        except ValueError:
            pass

    historico_analisado = []
    curr = primeira_data if registros else (hoje - timedelta(days=30))
    
    datas_intervalo = []
    temp_date = curr
    while temp_date <= hoje:
        datas_intervalo.append(temp_date)
        temp_date += timedelta(days=1)
    
    datas_intervalo.sort(reverse=True)

    for d_obj in datas_intervalo:
        data_str = d_obj.strftime("%d/%m/%Y")
        registros_do_dia = dias_registrados.get(d_obj, [])
        
        # Se for fim de semana (sábado=5, domingo=6) e NÃO houver registros, pula o dia
        is_fim_de_semana = d_obj.weekday() >= 5
        if is_fim_de_semana and not registros_do_dia:
            continue

        faltantes = identificar_pontos_faltantes(registros_do_dia)
        
        historico_analisado.append({
            "data": data_str,
            "registros": registros_do_dia,
            "faltantes": faltantes,
            "incompleto": len(faltantes) > 0,
        })

    return render_template(
        "meu_historico.html", historico=historico_analisado
    )

@app.route("/solicitar-correcao", methods=["GET", "POST"])
@login_required
def solicitar_correcao():
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()

    if request.method == "POST":
        data_raw = request.form.get("data_ponto")
        tipo_ponto = request.form.get("tipo_ponto")
        hora = request.form.get("hora_correta")
        justificativa = request.form.get("justificativa", "").strip()

        if not data_raw or not tipo_ponto or not hora or not justificativa:
            flash("Preencha todos os campos para solicitar a correção.", "warning")
            return redirect(url_for("solicitar_correcao"))

        data_obj = datetime.strptime(data_raw, "%Y-%m-%d").date()
        if data_obj > hoje:
            flash("Não é permitido solicitar ajuste para datas futuras.", "danger")
            return redirect(url_for("solicitar_correcao"))

        data_formatada = data_obj.strftime("%d/%m/%Y")
        
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

        flash("Solicitação de correção enviada com sucesso!", "info")
        return redirect(url_for("solicitar_correcao"))

    minhas_solicitacoes = SolicitacaoCorrecao.query.filter_by(
        usuario_id=current_user.id
    ).order_by(SolicitacaoCorrecao.id.desc()).all()

    return render_template(
        "solicitar_correcao.html", 
        solicitacoes=minhas_solicitacoes,
        data_hoje=hoje.strftime("%Y-%m-%d")
    )


@app.route("/exportar-pdf")
@login_required
def exportar_pdf():
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    registros = RegistroPonto.query.filter_by(usuario_id=current_user.id).all()

    dias_registrados = defaultdict(dict)
    primeira_data = hoje

    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            dias_registrados[d_obj][r.tipo] = r.hora
            if d_obj < primeira_data:
                primeira_data = d_obj
        except ValueError:
            pass

    tabela_linhas = [["Dia", "Entrada", "Almoço", "Retorno", "Saída", "Total / Status"]]
    
    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    total_segundos_faltantes = 0
    total_faltas_dias = 0
    
    FMT = "%H:%M:%S"
    segundos_carga_diaria = int(CARGA_HORARIA_DIARIA.total_seconds())  # 8h = 28800s

    curr = primeira_data
    while curr <= hoje:
        dia_str = curr.strftime("%d/%m/%Y")
        reg = dias_registrados.get(curr, {})

        if reg:
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

            # CÁLCULO DE HORAS EXTRAS / FALTANTES
            # Só contabiliza débito/crédito se for um dia passado OU se o dia de hoje já tiver sido finalizado (Saída registrada)
            if curr < hoje or s != "--:--":
                if tot > segundos_carga_diaria:
                    total_segundos_extras += (tot - segundos_carga_diaria)
                elif eh_dia_util(curr) and tot < segundos_carga_diaria:
                    total_segundos_faltantes += (segundos_carga_diaria - tot)

            hrs, mins = divmod(tot // 60, 60)
            tabela_linhas.append([dia_str, e, a, r, s, f"{hrs:02d}:{mins:02d}h"])

        elif eh_dia_util(curr):
            # Se for um dia útil no passado e sem nenhum registro -> É FALTA
            if curr < hoje:
                total_faltas_dias += 1
                total_segundos_faltantes += segundos_carga_diaria
                tabela_linhas.append([dia_str, "--:--", "--:--", "--:--", "--:--", "FALTA"])
            else:
                # Dia de hoje ainda em andamento sem registros
                tabela_linhas.append([dia_str, "--:--", "--:--", "--:--", "--:--", "Em Aberto"])

        curr += timedelta(days=1)

    # -------------------------------------------------------------
    # CÁLCULO DO BALANÇO FINAL
    # -------------------------------------------------------------
    balanco_segundos = total_segundos_extras - total_segundos_faltantes

    hrs_t, mins_t = divmod(total_segundos_trabalhados // 60, 60)
    hrs_e, mins_e = divmod(total_segundos_extras // 60, 60)
    hrs_f, mins_f = divmod(total_segundos_faltantes // 60, 60)
    
    hrs_b, mins_b = divmod(abs(balanco_segundos) // 60, 60)
    
    if balanco_segundos >= 0:
        texto_balanco = f"+{hrs_b:02d}:{mins_b:02d}h (Crédito)"
        cor_balanco = colors.HexColor("#2e7d32")
    else:
        texto_balanco = f"-{hrs_b:02d}:{mins_b:02d}h (A Repor)"
        cor_balanco = colors.HexColor("#c62828")

    # -------------------------------------------------------------
    # GERANDO O PDF (REPORTLAB)
    # -------------------------------------------------------------
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elementos = []
    estilos = getSampleStyleSheet()

    titulo_estilo = ParagraphStyle("T", parent=estilos["Heading1"], fontSize=18, alignment=1, spaceAfter=15)
    elementos.append(Paragraph(f"<b>Folha de Ponto - {current_user.nome}</b>", titulo_estilo))
    elementos.append(Paragraph(f"<b>E-mail:</b> {current_user.email} | <b>Emissão:</b> {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y às %H:%M')}", estilos["Normal"]))
    elementos.append(Spacer(1, 15))

    tabela = Table(tabela_linhas, colWidths=[80, 85, 85, 85, 85, 90])
    
    estilo_tabela = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ]

    for i, linha in enumerate(tabela_linhas[1:], start=1):
        if linha[5] == "FALTA":
            estilo_tabela.append(("TEXTCOLOR", (0, i), (-1, i), colors.HexColor("#d32f2f")))
            estilo_tabela.append(("FONTNAME", (0, i), (-1, i), "Helvetica-Bold"))
            estilo_tabela.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffebee")))

    tabela.setStyle(TableStyle(estilo_tabela))
    elementos.append(tabela)
    elementos.append(Spacer(1, 20))

    dados_resumo = [
        ["Horas Totais Trabalhadas:", f"{hrs_t:02d}:{mins_t:02d}h"],
        ["(+) Total Horas Extras:", f"{hrs_e:02d}:{mins_e:02d}h"],
        ["(-) Total Horas Faltantes:", f"{hrs_f:02d}:{mins_f:02d}h ({total_faltas_dias} dia(s) ausente)"],
        ["BALANÇO FINAL (BANCO DE HORAS):", texto_balanco],
    ]
    
    tabela_resumo = Table(dados_resumo, colWidths=[310, 200])
    tabela_resumo.setStyle(
        TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#2e7d32")),
            ("TEXTCOLOR", (1, 2), (1, 2), colors.HexColor("#c62828")),
            ("TEXTCOLOR", (1, 3), (1, 3), cor_balanco),
            ("LINEABOVE", (0, 3), (-1, 3), 1, colors.HexColor("#000000")),
        ])
    )
    elementos.append(tabela_resumo)

    pdf.build(elementos)
    buffer.seek(0)

    agora_br = datetime.now(ZoneInfo("America/Sao_Paulo"))
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Folha_Ponto_{current_user.nome.replace(' ', '_')}_{agora_br.strftime('%m_%Y')}.pdf",
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

def admin_panel():
    # Isso seria uma query no seu banco de dados, ex:
    # logs = RegistroPonto.query.order_by(RegistroPonto.data.desc()).limit(5).all()
    
    # Exemplo de como formatar os dados para o template:
    logs_recentes = [
        {"nome": "João Silva", "horario": "10:15", "descricao": "Registrou entrada", "tipo": "entrada", "icone": "bi-door-open"},
        {"nome": "Maria Souza", "horario": "09:30", "descricao": "Ajuste de ponto solicitado", "tipo": "alerta", "icone": "bi-pencil-square"},
        {"nome": "Pedro Santos", "horario": "08:00", "descricao": "Registrou entrada", "tipo": "entrada", "icone": "bi-door-open"}
    ]
    
    return render_template('admin_panel.html', logs_recentes=logs_recentes,  )

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

    if usuario_id:
        query = query.filter(RegistroPonto.usuario_id == usuario_id)

    if busca_nome:
        query = query.filter((Usuario.nome.ilike(f"%{busca_nome}%")) | (Usuario.email.ilike(f"%{busca_nome}%")))

    if tipo_ponto:
        query = query.filter(RegistroPonto.tipo == tipo_ponto)

    registros = query.order_by(RegistroPonto.id.desc()).all()

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
        
        ponto_existente = RegistroPonto.query.filter_by(
            usuario_id=solicitacao.usuario_id,
            data=solicitacao.data_ponto,
            tipo=solicitacao.tipo_ponto
        ).first()

        if ponto_existente:
            ponto_existente.hora = solicitacao.hora_correta
            ponto_existente.foi_ajustado = True
        else:
            novo_ponto = RegistroPonto(
                data=solicitacao.data_ponto,
                tipo=solicitacao.tipo_ponto,
                hora=solicitacao.hora_correta,
                usuario_id=solicitacao.usuario_id,
                foi_ajustado=True
            )
            db.session.add(novo_ponto)

        flash("Solicitação APROVADA e registro atualizado!", "success")

    elif acao == "recusar":
        solicitacao.status = "Recusada"
        flash("Solicitação RECUSADA.", "warning")

    db.session.commit()
    return redirect(url_for("admin_solicitacoes"))


@app.route("/admin/usuarios")
@login_required
def admin_usuarios():
    # Garante que apenas administradores acessem
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))
        
    usuarios = Usuario.query.all()
    
    # Calcula solicitações pendentes para o badge do menu superior
    total_solicitacoes_pendentes = 0
    try:
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    except Exception:
        pass
    
    return render_template(
        "admin_usuarios.html", 
        usuarios=usuarios, 
        total_solicitacoes_pendentes=total_solicitacoes_pendentes
    )

@app.route("/admin/toggle-admin/<int:user_id>", methods=["POST"])
@login_required
def toggle_admin(user_id):
    # Garante que apenas administradores alterem permissões
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))
    
    user = Usuario.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash("Você não pode alterar suas próprias permissões de administrador.", "warning")
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"Permissões do usuário {user.nome} atualizadas com sucesso!", "success")
        
    return redirect(url_for("admin_usuarios"))

@app.route('/admin/exportar-relatorio')
@login_required
def admin_exportar_relatorio():
    # Lógica para gerar e exportar o relatório (ex: Excel, CSV ou PDF)
    # Por enquanto, redirecionamos de volta ao painel com uma mensagem de sucesso
    flash('Relatório exportado com sucesso!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/usuarios/novo', methods=['GET', 'POST'])
@login_required
def admin_usuarios_novo():
    # Rota para cadastrar um novo colaborador pelo painel administrativo
    return redirect(url_for('admin_usuarios'))

@app.route("/admin/exportar-ponto/<int:user_id>")
@login_required
def admin_exportar_ponto(user_id):
    # 1. Validação de Administrador
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))

    # 2. Buscar o usuário específico pelo ID
    # IMPORTANTE: Verifique se o nome da sua classe de usuário é 'Usuario' ou 'User'
    usuario = Usuario.query.get_or_404(user_id)

    # 3. Buscar registros desse usuário
    # IMPORTANTE: Verifique se o nome da sua classe de registros é 'RegistroPonto'
    registros = RegistroPonto.query.filter_by(usuario_id=user_id).all()

    # --- LÓGICA COPIADA DA SUA ROTA ORIGINAL ---
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    dias_registrados = defaultdict(dict)
    primeira_data = hoje

    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            dias_registrados[d_obj][r.tipo] = r.hora
            if d_obj < primeira_data:
                primeira_data = d_obj
        except ValueError:
            pass

    tabela_linhas = [["Dia", "Entrada", "Almoço", "Retorno", "Saída", "Total / Status"]]
    
    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    total_segundos_faltantes = 0
    total_faltas_dias = 0
    
    FMT = "%H:%M:%S"
    segundos_carga_diaria = int(CARGA_HORARIA_DIARIA.total_seconds())

    curr = primeira_data
    while curr <= hoje:
        dia_str = curr.strftime("%d/%m/%Y")
        reg = dias_registrados.get(curr, {})

        if reg:
            e = reg.get("Entrada", "--:--")
            a = reg.get("Almoço", "--:--")
            r_ponto = reg.get("Retorno", "--:--") # Renomeado para não conflitar com variável 'r'
            s = reg.get("Saída", "--:--")

            tempo_trabalhado = timedelta()

            if e != "--:--" and a != "--:--":
                t1, t2 = datetime.strptime(e, FMT), datetime.strptime(a, FMT)
                if t2 > t1: tempo_trabalhado += t2 - t1

            if r_ponto != "--:--" and s != "--:--":
                t3, t4 = datetime.strptime(r_ponto, FMT), datetime.strptime(s, FMT)
                if t4 > t3: tempo_trabalhado += t4 - t3

            tot = int(tempo_trabalhado.total_seconds())
            total_segundos_trabalhados += tot

            if curr < hoje or s != "--:--":
                if tot > segundos_carga_diaria:
                    total_segundos_extras += (tot - segundos_carga_diaria)
                elif eh_dia_util(curr) and tot < segundos_carga_diaria:
                    total_segundos_faltantes += (segundos_carga_diaria - tot)

            hrs, mins = divmod(tot // 60, 60)
            tabela_linhas.append([dia_str, e, a, r_ponto, s, f"{hrs:02d}:{mins:02d}h"])

        elif eh_dia_util(curr):
            if curr < hoje:
                total_faltas_dias += 1
                total_segundos_faltantes += segundos_carga_diaria
                tabela_linhas.append([dia_str, "--:--", "--:--", "--:--", "--:--", "FALTA"])
            else:
                tabela_linhas.append([dia_str, "--:--", "--:--", "--:--", "--:--", "Em Aberto"])

        curr += timedelta(days=1)

    # 4. Cálculo do Balanço e PDF (Usando dados do 'usuario' buscado)
    balanco_segundos = total_segundos_extras - total_segundos_faltantes
    hrs_t, mins_t = divmod(total_segundos_trabalhados // 60, 60)
    hrs_e, mins_e = divmod(total_segundos_extras // 60, 60)
    hrs_f, mins_f = divmod(total_segundos_faltantes // 60, 60)
    hrs_b, mins_b = divmod(abs(balanco_segundos) // 60, 60)
    
    cor_balanco = colors.HexColor("#2e7d32") if balanco_segundos >= 0 else colors.HexColor("#c62828")
    texto_balanco = f"+{hrs_b:02d}:{mins_b:02d}h (Crédito)" if balanco_segundos >= 0 else f"-{hrs_b:02d}:{mins_b:02d}h (A Repor)"

    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elementos = []
    estilos = getSampleStyleSheet()

    titulo_estilo = ParagraphStyle("T", parent=estilos["Heading1"], fontSize=18, alignment=1, spaceAfter=15)
    elementos.append(Paragraph(f"<b>Folha de Ponto - {usuario.nome}</b>", titulo_estilo))
    elementos.append(Paragraph(f"<b>E-mail:</b> {usuario.email} | <b>Emissão:</b> {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y às %H:%M')}", estilos["Normal"]))
    elementos.append(Spacer(1, 15))

    tabela = Table(tabela_linhas, colWidths=[80, 85, 85, 85, 85, 90])
    estilo_tabela = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ]
    for i, linha in enumerate(tabela_linhas[1:], start=1):
        if linha[5] == "FALTA":
            estilo_tabela.append(("TEXTCOLOR", (0, i), (-1, i), colors.HexColor("#d32f2f")))
            estilo_tabela.append(("FONTNAME", (0, i), (-1, i), "Helvetica-Bold"))
            estilo_tabela.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffebee")))

    tabela.setStyle(TableStyle(estilo_tabela))
    elementos.append(tabela)
    elementos.append(Spacer(1, 20))

    dados_resumo = [
        ["Horas Totais Trabalhadas:", f"{hrs_t:02d}:{mins_t:02d}h"],
        ["(+) Total Horas Extras:", f"{hrs_e:02d}:{mins_e:02d}h"],
        ["(-) Total Horas Faltantes:", f"{hrs_f:02d}:{mins_f:02d}h ({total_faltas_dias} dia(s) ausente)"],
        ["BALANÇO FINAL (BANCO DE HORAS):", texto_balanco],
    ]
    
    tabela_resumo = Table(dados_resumo, colWidths=[310, 200])
    tabela_resumo.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("TEXTCOLOR", (1, 3), (1, 3), cor_balanco),
        ("LINEABOVE", (0, 3), (-1, 3), 1, colors.HexColor("#000000")),
    ]))
    elementos.append(tabela_resumo)

    pdf.build(elementos)
    buffer.seek(0)

    agora_br = datetime.now(ZoneInfo("America/Sao_Paulo"))
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Folha_Ponto_{usuario.nome.replace(' ', '_')}_{agora_br.strftime('%m_%Y')}.pdf",
        mimetype="application/pdf",
    )

@app.route('/admin/enviar-lembrete-geral', methods=['POST'])
@login_required
def enviar_lembrete_geral():
    # Valida se é admin (ajuste conforme a sua regra de segurança)
    if not getattr(current_user, 'is_admin', False):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))

    mensagem = request.form.get('mensagem')

    if mensagem:
        # Busca todos os usuários do sistema
        usuarios = Usuario.query.all()

        for user in usuarios:
            nova_notificacao = Notificacao(
                usuario_id=user.id,
                titulo="Lembrete da Administração",
                mensagem=mensagem,
                tipo="info",  # Define o tipo (aparecerá no dropdown do sino)
                link="#"      # Pode colocar uma URL específica se quiser
            )
            db.session.add(nova_notificacao)
        
        db.session.commit()
        flash('Lembrete enviado com sucesso para todos os colaboradores!', 'success')
    else:
        flash('A mensagem do lembrete não pode estar vazia.', 'warning')

    return redirect(url_for('admin_panel'))

def index():
    # Busca apenas as notificações não lidas do usuário logado
    notificacoes_usuario = Notificacao.query.filter_by(
        usuario_id=current_user.id, 
        lida=False
    ).order_by(Notificacao.data_criacao.desc()).all()

    # Conta o total para acender a bolinha vermelha (pulse-badge) no sino
    total_notificacoes = len(notificacoes_usuario)

    # Restante da sua lógica de pontos...
    
    return render_template(
        'app.html', 
        notificacoes_usuario=notificacoes_usuario,
        total_notificacoes=total_notificacoes
    )

if __name__ == "__main__":
    app.run(debug=True)