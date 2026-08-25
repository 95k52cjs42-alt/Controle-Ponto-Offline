import io
import os
import re
import secrets
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime, timedelta, date
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    flash,
    get_flashed_messages,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
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
from itsdangerous import URLSafeTimedSerializer as Serializer
import resend
import dns.resolver

# Bibliotecas para a geração do PDF (ReportLab)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-apenas-para-desenvolvimento")
resend.api_key = os.environ.get("RESEND_API_KEY")
if not resend.api_key:
    print("AVISO: RESEND_API_KEY não configurada. E-mails não serão enviados.")

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
    if data_obj.weekday() >= 5:
        return False
    feriado = Feriado.query.filter_by(data=data_obj).first()
    return feriado is None

def verificar_conformidade_clt(data_anterior, hora_saida, data_atual, hora_entrada):
    """
    Verifica intervalo interjornada (mínimo 11h).
    """
    dt_saida = datetime.strptime(f"{data_anterior} {hora_saida}", "%d/%m/%Y %H:%M:%S")
    dt_entrada = datetime.strptime(f"{data_atual} {hora_entrada}", "%d/%m/%Y %H:%M:%S")
    return (dt_entrada - dt_saida) >= timedelta(hours=11)

def verificar_intervalo_almoco(hora_almoco, hora_retorno):
    """
    Verifica intervalo intrajornada (mínimo 1h).
    """
    t1 = datetime.strptime(hora_almoco, "%H:%M:%S")
    t2 = datetime.strptime(hora_retorno, "%H:%M:%S")
    return (t2 - t1) >= timedelta(hours=1)

def verificar_dominio_email(email):
    try:
        dominio = email.split('@')[1]
        records = dns.resolver.resolve(dominio, 'MX')
        return len(records) > 0
    except Exception:
        return False

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
    data_criacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

class LogAuditoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    acao = db.Column(db.String(200), nullable=False)
    entidade_id = db.Column(db.Integer, nullable=True)
    data_criacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

    usuario = db.relationship("Usuario", backref="logs")

class Feriado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False, unique=True)
    descricao = db.Column(db.String(100), nullable=False)

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmado = db.Column(db.Boolean, default=False)
    precisa_redefinir_senha = db.Column(db.Boolean, default=False)
    data_cadastro = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    pontos = db.relationship("RegistroPonto", backref="usuario", lazy=True)
    solicitacoes = db.relationship("SolicitacaoCorrecao", backref="usuario", lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return Usuario.query.get(user_id)

    def get_confirmation_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_confirmation_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return Usuario.query.get(user_id)

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
        if "email_confirmado" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN email_confirmado BOOLEAN DEFAULT FALSE;"))
        if "precisa_redefinir_senha" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN precisa_redefinir_senha BOOLEAN DEFAULT FALSE;"))
        if "data_cadastro" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN data_cadastro DATETIME;"))
            db.session.execute(text("UPDATE usuario SET data_cadastro = CURRENT_TIMESTAMP;"))

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
        # Busca a data de cadastro do usuário ou usa 30 dias atrás se não houver
        usuario_obj = Usuario.query.get(user_id)
        data_inicio_calculo = usuario_obj.data_cadastro.date() if usuario_obj and usuario_obj.data_cadastro else (hoje - timedelta(days=30))
        
        limite_busca = min(primeiro_registro_data, data_inicio_calculo)
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
            if not user.email_confirmado:
                flash("Por favor, confirme seu e-mail antes de acessar o sistema.", "warning")
                return render_template("login.html", email=email)
            
            login_user(user)
            
            if user.precisa_redefinir_senha:
                flash("Você precisa redefinir sua senha no primeiro acesso.", "info")
                return redirect(url_for("redefinir_senha_forca"))
            
            return redirect(url_for("index"))
        else:
            flash("E-mail ou senha incorretos.", "danger")
            return render_template("login.html", email=email)

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
            flash(f"O e-mail {email} já está cadastrado. Por favor, faça login.", "warning")
            return render_template("register.html", nome=nome, email=email)

        # Validação de senha
        if len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
            return render_template("register.html", nome=nome, email=email)
        if not re.search(r"[A-Z]", senha):
            flash("A senha deve conter pelo menos uma letra maiúscula.", "danger")
            return render_template("register.html", nome=nome, email=email)
        if not re.search(r"[a-z]", senha):
            flash("A senha deve conter pelo menos uma letra minúscula.", "danger")
            return render_template("register.html", nome=nome, email=email)
        if not re.search(r"\d", senha):
            flash("A senha deve conter pelo menos um número.", "danger")
            return render_template("register.html", nome=nome, email=email)
        if not re.search(r"[@#*]", senha):
            flash("A senha deve conter pelo menos um caractere especial (@, # ou *).", "danger")
            return render_template("register.html", nome=nome, email=email)

        # Validação de domínio
        if not verificar_dominio_email(email):
            flash("O domínio do e-mail é inválido ou não possui registros MX.", "danger")
            return render_template("register.html", nome=nome, email=email)

        # Preparar dados para confirmação (sem salvar no banco ainda)
        token_data = {
            'nome': nome,
            'email': email,
            'senha_hash': generate_password_hash(senha, method="scrypt")
        }
        s = Serializer(app.config['SECRET_KEY'])
        token = s.dumps(token_data)
        
        confirm_url = url_for('confirm_email', token=token, _external=True)
        
        try:
            resend.Emails.send({
                "from": "onboarding@resend.dev",
                "to": email,
                "subject": "Confirme seu e-mail",
                "html": f"<p>Olá {nome}, clique no link para confirmar seu e-mail: <a href='{confirm_url}'>{confirm_url}</a></p>"
            })
            flash("Link de confirmação enviado! Verifique seu e-mail para concluir o cadastro.", "success")
        except Exception as e:
            flash(f"Erro ao enviar e-mail: {str(e)}", "danger")
            return render_template("register.html", nome=nome, email=email)

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da conta.", "info")
    return redirect(url_for("login"))

@app.route("/redefinir_senha_forca", methods=["GET", "POST"])
@login_required
def redefinir_senha_forca():
    if request.method == "POST":
        senha = request.form.get("senha", "")

        # Validação completa de senha (mesma regra do cadastro/reset)
        if len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
            return render_template("redefinir_senha_forca.html")
        if not re.search(r"[A-Z]", senha):
            flash("A senha deve conter pelo menos uma letra maiúscula.", "danger")
            return render_template("redefinir_senha_forca.html")
        if not re.search(r"[a-z]", senha):
            flash("A senha deve conter pelo menos uma letra minúscula.", "danger")
            return render_template("redefinir_senha_forca.html")
        if not re.search(r"\d", senha):
            flash("A senha deve conter pelo menos um número.", "danger")
            return render_template("redefinir_senha_forca.html")
        if not re.search(r"[@#*]", senha):
            flash("A senha deve conter pelo menos um caractere especial (@, # ou *).", "danger")
            return render_template("redefinir_senha_forca.html")

        current_user.senha_hash = generate_password_hash(senha, method="scrypt")
        current_user.precisa_redefinir_senha = False
        db.session.commit()
        registrar_log(current_user.id, f"Redefiniu a própria senha (primeiro acesso)")
        flash("Senha alterada com sucesso!", "success")
        return redirect(url_for("index"))
    
    return render_template("redefinir_senha_forca.html")

@app.route("/admin/cadastrar_usuario", methods=["POST"])
@admin_required
def admin_cadastrar_usuario():
    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip()
    
    if not nome or not email:
        flash("Nome e e-mail são obrigatórios.", "danger")
        return redirect(url_for("admin_usuarios"))
    
    if Usuario.query.filter_by(email=email).first():
        flash(f"Usuário {email} já cadastrado.", "danger")
        return redirect(url_for("admin_usuarios"))
    
    # Criar usuário temporário para gerar o token
    senha_temporaria = secrets.token_urlsafe(32)
    novo_usuario = Usuario(
        nome=nome,
        email=email,
        senha_hash=generate_password_hash(senha_temporaria, method="scrypt"),
        precisa_redefinir_senha=True,
        email_confirmado=True
    )
    db.session.add(novo_usuario)
    db.session.commit()
    registrar_log(current_user.id, f"Cadastrou usuário {nome} ({email})")
    
    token = novo_usuario.get_reset_token()
    link_definir_senha = url_for("definir_senha_usuario", token=token, _external=True)
    
    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": email,
            "subject": "Bem-vindo ao 4Lab Orbit - Defina sua senha",
            "html": f"<p>Olá {nome}, seu cadastro foi realizado pelo administrador.</p><p>Clique no link abaixo para definir sua senha e acessar o sistema:</p><p><a href='{link_definir_senha}'>{link_definir_senha}</a></p>"
        })
        flash(f"Usuário {nome} cadastrado com sucesso! E-mail de convite enviado.", "success")
    except Exception as e:
        flash(f"Erro ao enviar e-mail: {e}", "danger")
        
    return redirect(url_for("admin_usuarios"))

@app.route("/definir_senha/<token>")
def definir_senha_usuario(token):
    usuario = Usuario.verify_reset_token(token)
    if not usuario:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("login"))
    
    login_user(usuario)
    usuario.precisa_redefinir_senha = True
    db.session.commit()
    return redirect(url_for("redefinir_senha_forca"))

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user = Usuario.query.filter_by(email=email).first()

        if user:
            token = user.get_reset_token()
            reset_link = url_for('reset_password', token=token, _external=True)
            try:
                resend.Emails.send({
                    "from": "onboarding@resend.dev",
                    "to": email,
                    "subject": "Redefinição de Senha",
                    "html": f"<p>Olá {user.nome}, clique no link para redefinir sua senha: <a href='{reset_link}'>{reset_link}</a></p>"
                })
                flash("E-mail de recuperação enviado com sucesso!", "success")
            except Exception as e:
                flash(f"Erro ao enviar e-mail: {str(e)}", "danger")
        else:
            # Por segurança, não informamos se o e-mail existe ou não
            flash("Se o e-mail estiver cadastrado, você receberá instruções para redefinir a senha.", "info")

    return render_template("forgot_password.html")

@app.route("/confirm_email/<token>")
def confirm_email(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=1800)
    except:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("login"))

    # Verifica se e-mail já existe
    if Usuario.query.filter_by(email=data['email']).first():
        flash("Este e-mail já foi confirmado/cadastrado.", "warning")
        return redirect(url_for("login"))

    # Cria o usuário
    is_first = Usuario.query.count() == 0
    novo_usuario = Usuario(
        nome=data['nome'],
        email=data['email'],
        senha_hash=data['senha_hash'],
        is_admin=is_first,
        email_confirmado=True
    )
    db.session.add(novo_usuario)
    db.session.commit()
    
    flash("E-mail confirmado com sucesso! Você já pode fazer login.", "success")
    return redirect(url_for("login"))

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    user = Usuario.verify_reset_token(token)
    if not user:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        senha = request.form.get("senha", "")

        # Validação de senha
        if len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
            return render_template("reset_password.html")
        if not re.search(r"[A-Z]", senha):
            flash("A senha deve conter pelo menos uma letra maiúscula.", "danger")
            return render_template("reset_password.html")
        if not re.search(r"[a-z]", senha):
            flash("A senha deve conter pelo menos uma letra minúscula.", "danger")
            return render_template("reset_password.html")
        if not re.search(r"\d", senha):
            flash("A senha deve conter pelo menos um número.", "danger")
            return render_template("reset_password.html")
        if not re.search(r"[@#*]", senha):
            flash("A senha deve conter pelo menos um caractere especial (@, # ou *).", "danger")
            return render_template("reset_password.html")

        user.senha_hash = generate_password_hash(senha, method="scrypt")
        db.session.commit()
        flash("Senha redefinida com sucesso! Faça seu login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

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

    total_solicitacoes_pendentes = 0
    if current_user.is_admin:
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()

    return render_template(
        "index.html",
        pontos_batidos=pontos_batidos,
        ultimo_ponto=ultimo_ponto,
        data_hoje=data_hoje,
        registros_hoje=pontos_hoje_objs,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes
    )

@app.route("/registrar/<tipo>", methods=["POST"])
@login_required
def registrar(tipo):
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    data_atual = agora.strftime("%d/%m/%Y")
    hora_atual = agora.strftime("%H:%M:%S")

    # Validação para evitar pontos duplicados do mesmo tipo no mesmo dia
    ponto_existente = RegistroPonto.query.filter_by(
        usuario_id=current_user.id,
        data=data_atual,
        tipo=tipo
    ).first()

    if ponto_existente:
        flash(f"Você já registrou o ponto de {tipo} hoje às {ponto_existente.hora}.", "warning")
        return redirect(url_for("index"))

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

        try:
            data_obj = datetime.strptime(data_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Data inválida. Verifique o valor informado.", "danger")
            return redirect(url_for("solicitar_correcao"))

        if data_obj > hoje:
            flash("Data inválida. Não é permitido solicitar ajuste para datas futuras.", "danger")
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

@app.route("/exportar-ponto")
@login_required
def exportar_historico_ponto():
    formato = request.args.get('format', 'pdf')
    user_id = current_user.id
    usuario = current_user
    registros = RegistroPonto.query.filter_by(usuario_id=user_id).all()
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    
    # Lógica de cálculo (adaptada de admin_exportar_ponto)
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

    curr = primeira_data if registros else hoje
    while curr <= hoje:
        dia_str = curr.strftime("%d/%m/%Y")
        reg = dias_registrados.get(curr, {})
        if reg:
            e = reg.get("Entrada", "--:--")
            a = reg.get("Almoço", "--:--")
            r_ponto = reg.get("Retorno", "--:--")
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

    # Exportação baseada no formato
    if formato == "pdf":
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        elementos = []
        estilos = getSampleStyleSheet()
        elementos.append(Paragraph(f"Folha de Ponto - {usuario.nome}", estilos["Heading1"]))
        tabela = Table(tabela_linhas)
        elementos.append(tabela)
        pdf.build(elementos)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name=f"Folha_Ponto_{usuario.nome}.pdf", mimetype="application/pdf")
    
    import pandas as pd
    df = pd.DataFrame(tabela_linhas[1:], columns=tabela_linhas[0])
    if formato == "excel":
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)
        output.seek(0)
        return send_file(output, as_attachment=True, download_name=f"Folha_Ponto_{usuario.nome}.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    
    if formato == "csv":
        output = io.StringIO()
        df.to_csv(output, index=False, encoding='utf-8-sig')
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode('utf-8-sig')), as_attachment=True, download_name=f"Folha_Ponto_{usuario.nome}.csv", mimetype="text/csv")

    return redirect(url_for("meu_historico"))
# ==========================================
#          ROTAS DE ADMINISTRAÇÃO
# ==========================================
def build_admin_logs_recentes(limit=5):
    logs = []
    limite_logs = max(limit, 1)

    registros = RegistroPonto.query.join(Usuario).order_by(RegistroPonto.id.desc()).all()
    for reg in registros:
        if not reg.usuario:
            continue

        nome = reg.usuario.nome
        horario = reg.hora[:5] if reg.hora else "--:--"
        data_obj = None
        try:
            data_obj = datetime.strptime(f"{reg.data} {reg.hora}", "%d/%m/%Y %H:%M:%S")
        except ValueError:
            try:
                data_obj = datetime.strptime(f"{reg.data} {reg.hora}", "%d/%m/%Y %H:%M")
            except ValueError:
                data_obj = datetime.now()

        tipo = reg.tipo.lower()
        if tipo == "entrada":
            icon = "bi-door-open"
            tipo_key = "entrada"
        elif tipo == "saída":
            icon = "bi-door-closed"
            tipo_key = "saida"
        elif tipo == "almoço":
            icon = "bi-cup-hot"
            tipo_key = "alerta"
        elif tipo == "retorno":
            icon = "bi-arrow-repeat"
            tipo_key = "entrada"
        else:
            icon = "bi-clock-history"
            tipo_key = "alerta"

        logs.append({
            "nome": nome,
            "horario": horario,
            "descricao": f"Registrou {reg.tipo}",
            "tipo": tipo_key,
            "icone": icon,
            "_timestamp": data_obj,
        })

    solicitacoes = SolicitacaoCorrecao.query.join(Usuario).order_by(SolicitacaoCorrecao.id.desc()).all()
    for sol in solicitacoes:
        if not sol.usuario:
            continue

        horario = sol.data_solicitacao.strftime("%H:%M") if sol.data_solicitacao else "--:--"
        status = (sol.status or "").strip()
        descricao = "Solicitou ajuste de ponto" if status.lower() == "pendente" else f"Solicitação {status.lower()}"
        logs.append({
            "nome": sol.usuario.nome,
            "horario": horario,
            "descricao": descricao,
            "tipo": "alerta",
            "icone": "bi-pencil-square",
            "_timestamp": sol.data_solicitacao or datetime.now(),
        })

    logs = sorted(logs, key=lambda item: item["_timestamp"], reverse=True)
    for log in logs:
        log.pop("_timestamp", None)

    return logs[:limite_logs]

def render_admin_shell(initial_view="painel", **context):
    return render_template("admin.html", initial_view=initial_view, **context)

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    usuarios = Usuario.query.all()
    total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    
    # Calcular indicadores para o gráfico inicial
    registros = RegistroPonto.query.all()
    dias_por_user = defaultdict(lambda: defaultdict(list))
    for r in registros:
        dias_por_user[r.usuario_id][r.data].append(r.tipo)
    
    conformes = 0
    incompletos = 0
    for user_id, dias in dias_por_user.items():
        for data, tipos in dias.items():
            if len(set(tipos)) == 4:
                conformes += 1
            else:
                incompletos += 1

    # Calcular fluxo semanal (últimos 5 dias)
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    dias_semana = [(hoje - timedelta(days=i)) for i in range(4, -1, -1)]
    labels_semana = [d.strftime("%d/%m") for d in dias_semana]
    dados_semana = []
    for d in dias_semana:
        count = RegistroPonto.query.filter_by(data=d.strftime("%d/%m/%Y")).count()
        dados_semana.append(count)

    return render_admin_shell(
        initial_view="painel",
        usuarios=usuarios,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
        logs_recentes=build_admin_logs_recentes(),
        conformes=conformes,
        incompletos=incompletos,
        labels_semana=labels_semana,
        dados_semana=dados_semana
    )

@app.route("/admin/fragment/<string:view_name>")
@login_required
@admin_required
def admin_fragment(view_name):
    if view_name == "painel":
        usuarios = Usuario.query.all()
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
        
        # Calcular indicadores
        registros = RegistroPonto.query.all()
        dias_por_user = defaultdict(lambda: defaultdict(list))
        for r in registros:
            dias_por_user[r.usuario_id][r.data].append(r.tipo)
        
        conformes = 0
        incompletos = 0
        for user_id, dias in dias_por_user.items():
            for data, tipos in dias.items():
                if len(set(tipos)) == 4:
                    conformes += 1
                else:
                    incompletos += 1
        
        # Calcular fluxo semanal (últimos 5 dias)
        hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
        dias_semana = [(hoje - timedelta(days=i)) for i in range(4, -1, -1)]
        labels_semana = [d.strftime("%d/%m") for d in dias_semana]
        dados_semana = []
        for d in dias_semana:
            count = RegistroPonto.query.filter_by(data=d.strftime("%d/%m/%Y")).count()
            dados_semana.append(count)
        
        # Feriados do mês atual
        mes_atual = hoje.month
        ano_atual = hoje.year
        feriados = Feriado.query.filter(db.extract('month', Feriado.data) == mes_atual, db.extract('year', Feriado.data) == ano_atual).all()
        
        # Calcular Banco de Horas por usuário
        usuarios_banco_horas = []
        for u in usuarios:
            registros_user = RegistroPonto.query.filter_by(usuario_id=u.id).all()
            
            dias_registrados = defaultdict(dict)
            for r in registros_user:
                try:
                    d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
                    dias_registrados[d_obj][r.tipo] = r.hora
                except ValueError:
                    pass
            
            total_segundos_trabalhados = 0
            total_segundos_extras = 0
            total_segundos_faltantes = 0
            total_faltas_dias = 0
            FMT = "%H:%M:%S"
            segundos_carga_diaria = int(CARGA_HORARIA_DIARIA.total_seconds())
            
            # Calcular a partir do primeiro registro até hoje
            if dias_registrados:
                primeira_data = min(dias_registrados.keys())
            else:
                primeira_data = hoje
            
            curr = primeira_data
            while curr <= hoje:
                reg = dias_registrados.get(curr, {})
                if reg:
                    e = reg.get("Entrada", "--:--")
                    a = reg.get("Almoço", "--:--")
                    r_ponto = reg.get("Retorno", "--:--")
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
                elif eh_dia_util(curr) and curr < hoje:
                    total_faltas_dias += 1
                    total_segundos_faltantes += segundos_carga_diaria
                curr += timedelta(days=1)
            
            balanco_segundos = total_segundos_extras - total_segundos_faltantes
            hrs_b, mins_b = divmod(abs(balanco_segundos) // 60, 60)
            saldo_str = f"{'+' if balanco_segundos >= 0 else '-'}{hrs_b:02d}:{mins_b:02d}h"
            
            usuarios_banco_horas.append({
                "id": u.id,
                "nome": u.nome,
                "saldo_segundos": balanco_segundos,
                "saldo_str": saldo_str,
                "total_extras": total_segundos_extras,
                "total_faltantes": total_segundos_faltantes,
                "total_faltas_dias": total_faltas_dias
            })
        
        # Alertas CLT
        alertas_clt = []
        for u in usuarios:
            regs = RegistroPonto.query.filter_by(usuario_id=u.id).order_by(RegistroPonto.id.desc()).limit(10).all()
            dias_agrupados = defaultdict(dict)
            for r in regs:
                dias_agrupados[r.data][r.tipo] = r.hora
            
            # Verificar intervalo de 11h entre dias (Interjornada)
            dias_ordenados = sorted(dias_agrupados.keys(), key=lambda d: datetime.strptime(d, "%d/%m/%Y"), reverse=True)
            for i in range(len(dias_ordenados) - 1):
                d_atual = dias_ordenados[i]
                d_anterior = dias_ordenados[i+1]
                
                # Regra: Saída dia anterior -> Entrada dia atual
                saida_ant = dias_agrupados[d_anterior].get("Saída")
                entrada_atual = dias_agrupados[d_atual].get("Entrada")
                
                if saida_ant and entrada_atual:
                    if not verificar_conformidade_clt(d_anterior, saida_ant, d_atual, entrada_atual):
                        alertas_clt.append({"nome": u.nome, "msg": f"Interjornada < 11h em {d_atual}"})
                        break
            
            # Verificar intervalo almoço (Intrajornada)
            for d in dias_ordenados:
                almoco = dias_agrupados[d].get("Almoço")
                retorno = dias_agrupados[d].get("Retorno")
                if almoco and retorno:
                    if not verificar_intervalo_almoco(almoco, retorno):
                        alertas_clt.append({"nome": u.nome, "msg": f"Intervalo almoço < 1h em {d}"})
                        break

        return render_template(
            "admin_fragment_painel.html",
            usuarios=usuarios,
            total_solicitacoes_pendentes=total_solicitacoes_pendentes,
            logs_recentes=build_admin_logs_recentes(),
            conformes=conformes,
            incompletos=incompletos,
            labels_semana=labels_semana,
            dados_semana=dados_semana,
            usuarios_banco_horas=usuarios_banco_horas,
            alertas_clt=alertas_clt,
            feriados=feriados,
            data_hoje=hoje
        )

    if view_name == "usuarios":
        usuarios = Usuario.query.all()
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
        return render_template("admin_fragment_usuarios.html", usuarios=usuarios, total_solicitacoes_pendentes=total_solicitacoes_pendentes)

    if view_name == "historico":
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
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
        return render_template(
            "admin_fragment_historico.html",
            registros=registros,
            usuarios=usuarios,
            usuario_id_selecionado=usuario_id,
            busca_nome=busca_nome,
            data_inicio=data_inicio,
            data_fim=data_fim,
            tipo_ponto=tipo_ponto,
            total_solicitacoes_pendentes=total_solicitacoes_pendentes,
        )

    if view_name == "solicitacoes":
        solicitacoes = SolicitacaoCorrecao.query.order_by(SolicitacaoCorrecao.id.desc()).all()
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter(
            db.func.lower(SolicitacaoCorrecao.status) == "pendente"
        ).count()
        return render_template(
            "admin_fragment_solicitacoes.html",
            solicitacoes=solicitacoes,
            total_solicitacoes_pendentes=total_solicitacoes_pendentes,
        )

    if view_name == "logs":
        logs = LogAuditoria.query.order_by(LogAuditoria.id.desc()).limit(100).all()
        return render_template("admin_fragment_logs.html", logs=logs)

    return redirect(url_for("admin_panel"))

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
    total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()

    return render_admin_shell(
        initial_view="historico",
        registros=registros,
        usuarios=usuarios,
        usuario_id_selecionado=usuario_id,
        busca_nome=busca_nome,
        data_inicio=data_inicio,
        data_fim=data_fim,
        tipo_ponto=tipo_ponto,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
    )

@app.route("/admin/solicitacoes")
@login_required
@admin_required
def admin_solicitacoes():
    solicitacoes = SolicitacaoCorrecao.query.order_by(SolicitacaoCorrecao.id.desc()).all()
    total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter(
        db.func.lower(SolicitacaoCorrecao.status) == "pendente"
    ).count()
    usuarios = Usuario.query.all()
    return render_admin_shell(
        initial_view="solicitacoes",
        solicitacoes=solicitacoes,
        usuarios=usuarios,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
    )

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

        registrar_log(current_user.id, f"Aprovou ajuste de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}", id)
        flash("Solicitação APROVADA e registro atualizado!", "success")

    elif acao == "recusar":
        solicitacao.status = "Recusada"
        registrar_log(current_user.id, f"Recusou ajuste de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}", id)
        flash("Solicitação RECUSADA.", "warning")

    db.session.commit()
    return redirect(url_for("admin_solicitacoes"))

@app.route("/admin/usuarios")
@login_required
@admin_required
def admin_usuarios():
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))

    usuarios = Usuario.query.all()
    total_solicitacoes_pendentes = 0
    try:
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    except Exception:
        pass

    return render_admin_shell(
        initial_view="usuarios",
        usuarios=usuarios,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
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
        registrar_log(current_user.id, f"Alterou permissão de admin para {user.nome} -> {user.is_admin}", user_id)
        flash(f"Permissões do usuário {user.nome} atualizadas com sucesso!", "success")
        
    return redirect(url_for("admin_usuarios"))

def registrar_log(usuario_id, acao, entidade_id=None):
    log = LogAuditoria(usuario_id=usuario_id, acao=acao, entidade_id=entidade_id)
    db.session.add(log)
    db.session.commit()

@app.route("/admin/excluir-usuario/<int:user_id>", methods=["POST"])
@login_required
def excluir_usuario(user_id):
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))
    
    user = Usuario.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash("Você não pode excluir sua própria conta.", "danger")
    else:
        # Não excluímos logs de auditoria para manter conformidade (Portaria 671)
        # Excluímos apenas registros de ponto e solicitações associadas
        user_nome = user.nome
        RegistroPonto.query.filter_by(usuario_id=user.id).delete()
        SolicitacaoCorrecao.query.filter_by(usuario_id=user.id).delete()
        Notificacao.query.filter_by(usuario_id=user.id).delete()
        
        db.session.delete(user)
        db.session.commit()
        
        registrar_log(current_user.id, f"Excluiu usuário {user_nome}", user_id)
        
        flash(f"Usuário {user_nome} excluído com sucesso!", "success")
        
    return redirect(url_for("admin_usuarios"))

@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    logs = LogAuditoria.query.order_by(LogAuditoria.id.desc()).limit(100).all()
    usuarios = Usuario.query.all()
    total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    return render_admin_shell(
        initial_view="logs",
        logs=logs,
        usuarios=usuarios,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
    )

@app.route('/admin/exportar-afd')
@login_required
@admin_required
def admin_exportar_afd():
    # Geração de arquivo simplificada conforme layout AFD (Portaria 671)
    registros = RegistroPonto.query.order_by(RegistroPonto.id.asc()).all()
    
    output = io.StringIO()
    # NSR (Número Sequencial de Registro)
    nsr = 1
    
    # Header (Tipo 1) - usa horário de Brasília
    agora_br = datetime.now(ZoneInfo("America/Sao_Paulo"))
    output.write(f"1{nsr:09d}{agora_br.strftime('%d%m%Y%H%M%S')}\n")
    nsr += 1
    
    # Detalhes (Tipo 2)
    for r in registros:
        # Simplificado para exemplo: 2|NSR|PIS(dummy)|DATA|HORA|TIPO
        # Em produção, exigiria campos específicos de PIS/REP
        output.write(f"2{nsr:09d}000000000000{r.data.replace('/', '')}{r.hora.replace(':', '')}{r.tipo[0]}\n")
        nsr += 1
    
    # Trailer (Tipo 9)
    output.write(f"9{nsr:09d}\n")
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        as_attachment=True,
        download_name="afd_export.txt",
        mimetype="text/plain"
    )

# Rota removida: cadastro é feito via modal no painel admin

@app.route("/admin/exportar-ponto/<int:user_id>")
@login_required
def admin_exportar_ponto(user_id):
    # 1. Validação de Administrador
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))

    formato = request.args.get('format', 'pdf')
    data_inicio = request.args.get('data_inicio', '').strip()
    data_fim = request.args.get('data_fim', '').strip()

    # 2. Buscar o usuário específico pelo ID
    # IMPORTANTE: Verifique se o nome da sua classe de usuário é 'Usuario' ou 'User'
    usuario = Usuario.query.get_or_404(user_id)

    # 3. Buscar registros desse usuário (com filtro opcional por período)
    query_registros = RegistroPonto.query.filter_by(usuario_id=user_id)
    registros = query_registros.order_by(RegistroPonto.id.asc()).all()

    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()

    # Período de exibição: padrão = desde o primeiro registro até hoje
    data_inicio_obj = None
    data_fim_obj = hoje
    if data_inicio:
        data_inicio_obj = datetime.strptime(data_inicio, "%Y-%m-%d").date()
    if data_fim:
        data_fim_obj = datetime.strptime(data_fim, "%Y-%m-%d").date()

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

    # Aplica filtro de período
    if data_inicio_obj:
        primeira_data = data_inicio_obj
    if data_fim_obj:
        hoje = data_fim_obj
        if primeira_data > hoje:
            primeira_data = hoje

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

    if formato == "pdf":
        pdf.build(elementos)
        buffer.seek(0)
        agora_br = datetime.now(ZoneInfo("America/Sao_Paulo"))
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"Folha_Ponto_{usuario.nome.replace(' ', '_')}_{agora_br.strftime('%m_%Y')}.pdf",
            mimetype="application/pdf",
        )

    import pandas as pd
    df = pd.DataFrame(tabela_linhas[1:], columns=tabela_linhas[0])

    if formato == "excel":
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Ponto')
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=f"Folha_Ponto_{usuario.nome.replace(' ', '_')}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    if formato == "csv":
        output = io.StringIO()
        df.to_csv(output, index=False, encoding='utf-8-sig')
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')),
            as_attachment=True,
            download_name=f"Folha_Ponto_{usuario.nome.replace(' ', '_')}.csv",
            mimetype="text/csv"
        )

    return redirect(url_for("admin_panel"))

@app.route("/admin/feriados/adicionar", methods=["POST"])
@login_required
@admin_required
def adicionar_feriado():
    data_str = request.form.get("data")
    descricao = request.form.get("descricao")
    try:
        data = datetime.strptime(data_str, "%Y-%m-%d").date()
        feriado = Feriado(data=data, descricao=descricao)
        db.session.add(feriado)
        db.session.commit()
        flash("Feriado cadastrado com sucesso!", "success")
    except Exception as e:
        flash(f"Erro ao cadastrar feriado: {e}", "danger")
    return redirect(url_for("admin_panel"))

@app.route("/admin/feriados/excluir/<int:id>", methods=["POST"])
@login_required
@admin_required
def excluir_feriado(id):
    feriado = Feriado.query.get_or_404(id)
    db.session.delete(feriado)
    db.session.commit()
    flash("Feriado excluído com sucesso!", "success")
    return redirect(url_for("admin_panel"))

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

if __name__ == "__main__":
    app.run(debug=True)