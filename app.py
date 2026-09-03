import io
import os
import re
import time
import holidays
import calendar

import secrets
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime, timedelta, date
from functools import wraps
from zoneinfo import ZoneInfo

import requests

from flask import (
    Flask,
    flash,
    get_flashed_messages,
    jsonify,
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
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

CARGA_HORARIA_DIARIA = timedelta(hours=8)

# Siglas e nomes das UFs brasileiras (para o seletor manual e validações)
UFS_BRASIL = {
    "AC": "Acre", "AL": "Alagoas", "AP": "Amapá", "AM": "Amazonas",
    "BA": "Bahia", "CE": "Ceará", "DF": "Distrito Federal", "ES": "Espírito Santo",
    "GO": "Goiás", "MA": "Maranhão", "MT": "Mato Grosso", "MS": "Mato Grosso do Sul",
    "MG": "Minas Gerais", "PA": "Pará", "PB": "Paraíba", "PR": "Paraná",
    "PE": "Pernambuco", "PI": "Piauí", "RJ": "Rio de Janeiro", "RN": "Rio Grande do Norte",
    "RS": "Rio Grande do Sul", "RO": "Rondônia", "RR": "Roraima", "SC": "Santa Catarina",
    "SP": "São Paulo", "SE": "Sergipe", "TO": "Tocantins",
}

# Cache curto da região para não consultar o banco a cada chamada de
# eh_dia_util/_feriados_do_mes (que acontecem em loops de meses inteiros).
_REGIAO_CACHE = {"momento": 0.0, "regiao": None}
_REGIAO_CACHE_TTL = 30  # segundos

# Janela (em dias corridos) usada para calcular o alerta de faltas no painel
# de notificações. Limita a varredura ao período recente, evitando consultar
# todo o histórico do usuário a cada request (que causava lentidão em produção).
NOTIF_JANELA_DIAS = 30

# Cache em memória das notificações por usuário (TTL curto) para evitar
# recalcular o alerta de faltas/pontos incompletos a cada request.
# Estrutura: {user_id: {"momento": float, "notifs": [...]}}
_NOTIF_CACHE = {}
_NOTIF_CACHE_TTL = 30  # segundos

# Cache em memória dos feriados (banco + biblioteca) por ano/região, para que
# eh_dia_util e os loops de faltas não reconsultem o banco dia a dia.
# Estrutura: {(ano, subdiv): {"momento": float, "feriados_db": set, "ignorados": set, "lib": set}}
_FERIADOS_CACHE = {}
_FERIADOS_CACHE_TTL = 300  # segundos (5 min)

# API de reverse geocoding gratuita e sem chave (BigDataCloud)
BIGDATACLOUD_URL = "https://api.bigdatacloud.net/data/reverse-geocode-client"


def _get_config(chave, default=None):
    """Lê um valor da tabela de configurações (None se ausente)."""
    try:
        reg = Configuracao.query.get(chave)
        return reg.valor if reg is not None else default
    except Exception:
        return default


def _set_config(chave, valor):
    """Grava/atualiza um valor na tabela de configurações."""
    reg = Configuracao.query.get(chave)
    if reg is not None:
        reg.valor = valor
    else:
        db.session.add(Configuracao(chave=chave, valor=valor))


def _resolver_regiao():
    """Resolve a região vigente dos feriados.

    Precedência:
      1. UF persistida na tabela ``configuracao`` (detectada por geolocalização
         ou definida manualmente pelo admin);
      2. variável de ambiente ``ESTADO_FERIADO`` (fallback do servidor);
      3. ``'BR'`` (somente feriados nacionais).

    Retorna ``(uf, cidade, fonte)``, onde ``fonte`` é ``''`` (nada configurado),
    ``'env'``, ``'manual'`` ou ``'geo'``.
    """
    uf = _get_config("uf_feriado")
    if uf:
        uf = uf.strip().upper()
        cidade = _get_config("cidade_feriado", "") or ""
        fonte = (_get_config("regiao_fonte", "") or "").strip().lower()
        return uf, cidade, fonte
    estado_env = os.environ.get("ESTADO_FERIADO", "").strip().upper()
    if estado_env:
        return estado_env, "", "env"
    return "BR", "", ""


def _regiao_feriados(usar_cache=True):
    """Retorna ``(estado, subdiv)`` conforme a região configurada.

    Ex.: ``('SP', 'SP')`` (nacionais + estaduais de SP) ou ``('BR', None)``
    (somente nacionais). O cache evita consultas repetidas ao banco.
    """
    global _REGIAO_CACHE
    agora = time.time()
    if not (
        usar_cache
        and _REGIAO_CACHE["regiao"] is not None
        and agora - _REGIAO_CACHE["momento"] < _REGIAO_CACHE_TTL
    ):
        _REGIAO_CACHE = {"momento": agora, "regiao": _resolver_regiao()}
    estado, _, _ = _REGIAO_CACHE["regiao"]
    subdiv = estado if estado != "BR" else None
    return estado, subdiv


def _regiao_display():
    """Resolução sem cache para os templates (badges/selectors)."""
    return _resolver_regiao()


def _invalidar_cache_regiao():
    """Força a região a ser relida da configuração na próxima chamada."""
    global _REGIAO_CACHE
    _REGIAO_CACHE = {"momento": 0.0, "regiao": None}
    # Ao trocar a região, os feriados da biblioteca mudam também
    _FERIADOS_CACHE.clear()


def _invalidar_notif_cache(user_id=None):
    """Invalida o cache de notificações de um ou todos os usuários."""
    if user_id is not None:
        _NOTIF_CACHE.pop(user_id, None)
    else:
        _NOTIF_CACHE.clear()


def _carregar_feriados(ano, subdiv):
    """Carrega (com cache) os feriados do banco + biblioteca para um ano/região.

    Retorna ``(feriados_db: set[date], ignorados: set[date], lib: set[date])``.
    Evita reconsultar o banco e recriar o objeto ``holidays`` a cada chamada
    de ``eh_dia_util``.
    """
    agora = time.time()
    chave = (ano, subdiv)
    cached = _FERIADOS_CACHE.get(chave)
    if cached and (agora - cached["momento"]) < _FERIADOS_CACHE_TTL:
        return cached["feriados_db"], cached["ignorados"], cached["lib"]

    # 1 query para feriados do ano, 1 query para ignorados do ano
    feriados_db = {
        f.data
        for f in Feriado.query.filter(
            Feriado.data >= date(ano, 1, 1),
            Feriado.data <= date(ano, 12, 31),
        ).all()
    }
    ignorados = {
        ig.data
        for ig in FeriadoIgnorado.query.filter(
            FeriadoIgnorado.data >= date(ano, 1, 1),
            FeriadoIgnorado.data <= date(ano, 12, 31),
        ).all()
    }

    lib = set()
    try:
        br_holidays = holidays.country_holidays("BR", subdiv=subdiv, years=ano)
        lib = set(br_holidays.keys())
    except Exception:
        pass

    _FERIADOS_CACHE[chave] = {
        "momento": agora,
        "feriados_db": feriados_db,
        "ignorados": ignorados,
        "lib": lib,
    }
    return feriados_db, ignorados, lib


def _reverse_geocode(lat, lng):
    """Converte coordenadas em ``(uf, cidade)`` via API BigDataCloud.

    Retorna ``(None, None)`` caso não consiga resolver ou o ponto não esteja
    no Brasil. As coordenadas não são armazenadas em lugar nenhum.
    """
    try:
        resp = requests.get(
            BIGDATACLOUD_URL,
            params={
                "latitude": lat,
                "longitude": lng,
                "localityLanguage": "pt",
            },
            timeout=8,
        )
        if resp.status_code != 200:
            return None, None
        dados = resp.json()
        if str(dados.get("countryCode", "")).upper() != "BR":
            return None, None
        codigo = dados.get("principalSubdivisionCode") or ""
        # Ex.: "BR-SP" -> "SP"
        uf = codigo.split("-")[-1].strip().upper() if codigo else ""
        if uf not in UFS_BRASIL:
            return None, None
        cidade = (dados.get("locality") or dados.get("city") or "").strip()
        return uf, cidade
    except Exception:
        return None, None


# Função auxiliar para verificar se a data cai em dia útil (Segunda a Sexta)
def eh_dia_util(data_obj):
    if data_obj.weekday() >= 5:
        return False

    try:
        # Usa cache de feriados (banco + biblioteca) para não reconsultar o
        # banco e recriar o objeto holidays a cada chamada.
        _, subdiv = _regiao_feriados()
        feriados_db, ignorados, lib = _carregar_feriados(data_obj.year, subdiv)

        # Feriado excluído pelo admin -> tratado como dia útil normal
        if data_obj in ignorados:
            return True

        # Verifica feriado no banco de dados
        if data_obj in feriados_db:
            return False

        # Verifica feriado na biblioteca (nacionais + estaduais da UF configurada)
        if data_obj in lib:
            return False
    except Exception:
        # Em caso de erro ao acessar banco ou biblioteca de feriados,
        # trata como dia útil (mesma proteção do código original).
        pass

    return True

class FeriadoObj:
    """Objeto simples para passar dados de feriado ao template."""
    def __init__(self, data, descricao, id=None, fonte="manual"):
        self.data = data
        self.descricao = descricao
        self.id = id
        self.fonte = fonte

def _sincronizar_feriados_lib(anos=None):
    """Insere no banco os feriados da biblioteca `holidays` (nacionais + os
    estaduais da UF em ESTADO_FERIADO) para os anos pedidos, sem duplicar nem
    recriar os que o admin já excluiu. Retorna o número de feriados inseridos.

    Também remove feriados ``fonte='auto'`` que deixaram de existir ao trocar
    de estado, para o banco refletir a configuração atual.
    """
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    if anos is None:
        anos = {hoje.year - 1, hoje.year, hoje.year + 1}
    anos = set(anos)

    try:
        _, subdiv = _regiao_feriados()
        br_holidays = holidays.country_holidays("BR", subdiv=subdiv, years=list(anos))
    except Exception as e:
        print(f"AVISO: não foi possível carregar feriados da biblioteca: {e}")
        return 0

    ignorados = {ig.data for ig in FeriadoIgnorado.query.all()}
    # Datas atuais de feriados automáticos no intervalo dos anos sincronizados
    existente_auto = {
        f.data: f for f in Feriado.query.filter(
            Feriado.fonte == "auto",
            Feriado.data >= date(min(anos), 1, 1),
            Feriado.data <= date(max(anos), 12, 31),
        ).all()
    }

    inseridos = 0

    # 1) Remove feriados automáticos que não fazem parte da região atual
    datas_lib = set(br_holidays.keys())
    for data_auto, feriado in list(existente_auto.items()):
        if data_auto not in datas_lib:
            db.session.delete(feriado)

    # 2) Insere os faltantes (respeitando os ignorados/existentes)
    for dt, name in br_holidays.items():
        if dt in ignorados:
            continue
        if dt in existente_auto:
            continue
        if Feriado.query.filter_by(data=dt).first():
            continue
        db.session.add(Feriado(data=dt, descricao=name, fonte="auto"))
        inseridos += 1

    try:
        db.session.commit()
        _FERIADOS_CACHE.clear()
    except Exception:
        db.session.rollback()
        raise
    return inseridos

def _feriados_do_mes(hoje):
    """Retorna lista de FeriadoObj (DB + biblioteca) para o mês de ``hoje``."""
    mes_atual = hoje.month
    ano_atual = hoje.year
    _, last_day = calendar.monthrange(ano_atual, mes_atual)
    start_date = date(ano_atual, mes_atual, 1)
    end_date = date(ano_atual, mes_atual, last_day)

    feriados_db = Feriado.query.filter(
        Feriado.data >= start_date, Feriado.data <= end_date
    ).all()

    ignorados = {ig.data for ig in FeriadoIgnorado.query.filter(
        FeriadoIgnorado.data >= start_date, FeriadoIgnorado.data <= end_date
    ).all()}

    feriados = []
    # Feriados cadastrados no banco (ignorando os excluídos pelo admin)
    for f in feriados_db:
        if f.data in ignorados:
            continue
        feriados.append(FeriadoObj(f.data, f.descricao, f.id, f.fonte))

    # Feriados da biblioteca (se não estiverem já no DB)
    try:
        _, subdiv = _regiao_feriados()
        br_holidays = holidays.country_holidays("BR", subdiv=subdiv, years=ano_atual)
        datas_db = {f.data for f in feriados_db}
        for dt, name in br_holidays.items():
            if dt.year == ano_atual and dt.month == mes_atual:
                if dt not in datas_db and dt not in ignorados:
                    feriados.append(FeriadoObj(dt, name, fonte="auto"))
    except Exception:
        pass

    feriados.sort(key=lambda x: x.data)
    return feriados

def verificar_conformidade_clt(data_anterior, hora_saida, data_atual, hora_entrada):
    """
    Verifica intervalo interjornada (mínimo 11h).
    """
    dt_saida = datetime.strptime(f"{data_anterior} {hora_saida}", "%d/%m/%Y %H:%M:%S")
    dt_entrada = datetime.strptime(f"{data_atual} {hora_entrada}", "%d/%m/%Y %H:%M:%S")
    return (dt_entrada - dt_saida) >= timedelta(hours=11)

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

class Departamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True)
    descricao = db.Column(db.String(255), nullable=True)
    data_criacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    usuarios = db.relationship("Usuario", backref="departamento_rel", lazy=True)

class Feriado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False, unique=True)
    descricao = db.Column(db.String(100), nullable=False)
    fonte = db.Column(db.String(20), nullable=False, default="manual")  # "manual" | "auto"


class FeriadoIgnorado(db.Model):
    """Feriados que o admin excluiu/rejeitou e não devem ser readicionados
    pelo sincronizador automático, nem contar como dia não útil."""
    data = db.Column(db.Date, primary_key=True)


class Configuracao(db.Model):
    """Configurações globais de chave/valor da aplicação.

    Chaves usadas hoje:
      - ``uf_feriado``: UF que define os feriados estaduais ('SP', 'RJ', ...)
        ou 'BR' implícito pela ausência;
      - ``cidade_feriado``: cidade detectada (apenas informativa);
      - ``regiao_fonte``: como a região foi definida ('geo' | 'manual').
    """
    chave = db.Column(db.String(50), primary_key=True)
    valor = db.Column(db.String(255), nullable=False)

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmado = db.Column(db.Boolean, default=False)
    precisa_redefinir_senha = db.Column(db.Boolean, default=False)
    foto_url = db.Column(db.String(255), nullable=True)
    departamento_id = db.Column(db.Integer, db.ForeignKey('departamento.id'), nullable=True)
    permissoes = db.Column(db.Text, nullable=True) # Guarda JSON ex: {"pode_ver_dashboard": true, ...}
    data_cadastro = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    pontos = db.relationship("RegistroPonto", backref="usuario", lazy=True)
    solicitacoes = db.relationship("SolicitacaoCorrecao", backref="usuario", lazy=True)

    def tem_permissao(self, permissao):
        if self.is_admin:
            return True
        if not self.permissoes:
            return False
        try:
            import json
            perms = json.loads(self.permissoes)
            return perms.get(permissao, False)
        except:
            return False

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
            if db.engine.name == "postgresql":
                db.session.execute(text("ALTER TABLE usuario ADD COLUMN data_cadastro TIMESTAMP;"))
            else:
                db.session.execute(text("ALTER TABLE usuario ADD COLUMN data_cadastro DATETIME;"))
            db.session.execute(text("UPDATE usuario SET data_cadastro = CURRENT_TIMESTAMP;"))

        if "foto_url" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN foto_url VARCHAR(255);"))
        if "departamento_id" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN departamento_id INTEGER;"))
        if "permissoes" not in colunas_usuario:
            db.session.execute(text("ALTER TABLE usuario ADD COLUMN permissoes TEXT;"))

        colunas_ponto = [c["name"] for c in inspector.get_columns("registro_ponto")]
        if "foi_ajustado" not in colunas_ponto:
            db.session.execute(text("ALTER TABLE registro_ponto ADD COLUMN foi_ajustado BOOLEAN DEFAULT FALSE;"))

        colunas_feriado = [c["name"] for c in inspector.get_columns("feriado")]
        if "fonte" not in colunas_feriado:
            db.session.execute(text("ALTER TABLE feriado ADD COLUMN fonte VARCHAR(20) DEFAULT 'manual';"))

        db.session.commit()
    except Exception as e:
        db.session.rollback()

    # Garante que os feriados nacionais + estaduais (ESTADO_FERIADO) estejam
    # cadastrados no banco já na inicialização do app.
    try:
        _sincronizar_feriados_lib()
    except Exception as e:
        print(f"AVISO: falha ao sincronizar feriados na inicialização: {e}")

# ==========================================
#         SISTEMA DE NOTIFICAÇÕES
# ==========================================

PONTOS_PERMITIDOS = ["Entrada", "Saída"]

def identificar_pontos_faltantes(registros_do_dia):
    """
    Dado uma lista de registros de um único dia (em ordem cronológica),
    retorna o próximo tipo que o funcionário deve bater.

    - Se não há registros ou o último é "Saída" -> faltante: "Entrada"
    - Se o último é "Entrada" -> faltante: "Saída"
    """
    tipos = [
        getattr(p, "tipo", getattr(p, "tipo_ponto", ""))
        for p in registros_do_dia
    ]
    # Considera apenas entradas/saídas (ignora dados antigos do tipo Almoço/Retorno)
    seq = [t for t in tipos if t in PONTOS_PERMITIDOS]
    if not seq or seq[-1] == "Saída":
        return ["Entrada"]
    return ["Saída"]


def dia_ponto_incompleto(registros_do_dia):
    """
    No novo modelo de pares Entrada/Saída ilimitados, considera-se o dia
    INCOMPLETO quando existe uma Entrada sem a correspondente Saída de fechamento
    (ou seja, sobra uma Entrada "em aberto" no registro do dia).

    Retorna True se o dia está aberto (faltou bater a Saída correspondente),
    False caso contrário (dia completo ou sem registros).
    """
    tipos = [
        getattr(p, "tipo", getattr(p, "tipo_ponto", ""))
        for p in registros_do_dia
    ]
    seq = [t for t in tipos if t in PONTOS_PERMITIDOS]
    if not seq:
        return False
    # Aberto se a última batida foi uma Entrada sem Saída de fechamento
    return seq[-1] == "Entrada"


def _parse_hora(valor):
    """Converte uma string de hora (HH:MM ou HH:MM:SS) para datetime.time."""
    if not valor:
        return None
    valor = valor.strip()
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(valor, fmt).time()
        except ValueError:
            continue
    return None


def calcular_saldo_dia(registros_do_dia, data_obj):
    """
    Calcula o tempo trabalhado no dia e o saldo em relação à carga horária diária.

    O tempo é calculado pareando Entradas e Saídas em ordem cronológica:
      trabalhado = Σ (Saída[i] - Entrada[i])
    Se sobrar uma Entrada sem Saída correspondente e for o dia atual,
    o tempo parcial é calculado até o momento atual.

    Retorna um dict com:
      - total_trabalhado_seg: segundos totais trabalhados
      - total_trabalhado_fmt: string formatada (ex: "07:15h")
      - diferenca_seg: diferença em segundos (negativo=faltante, positivo=extra)
      - diferenca_fmt: string formatada (ex: "-45min" ou "+30min")
      - is_excedente: True se trabalhou mais que a carga diária
      - is_faltante: True se trabalhou menos que a carga diária
      - tem_registro: True se houve ao menos 1 batida no dia
    """
    carga_seg = int(CARGA_HORARIA_DIARIA.total_seconds())

    tempo_trabalhado = timedelta()
    tem_registro = len(registros_do_dia) > 0

    if not tem_registro:
        h_falt, m_falt = divmod(carga_seg // 60, 60)
        return {
            "total_trabalhado_seg": 0,
            "total_trabalhado_fmt": "--:--",
            "diferenca_seg": -carga_seg,
            "diferenca_fmt": f"-{h_falt:02d}:{m_falt:02d}h",
            "is_excedente": False,
            "is_faltante": True,
            "tem_registro": False,
        }

    # Separa entradas e saídas em ordem cronológica de registro
    entradas = []
    saidas = []
    for p in registros_do_dia:
        tipo = getattr(p, "tipo", getattr(p, "tipo_ponto", ""))
        hora = getattr(p, "hora", None)
        if not tipo or not hora:
            continue
        if tipo == "Entrada":
            entradas.append(hora)
        elif tipo == "Saída":
            saidas.append(hora)

    # Pareia Entrada[i] -> Saída[i]
    for i in range(min(len(entradas), len(saidas))):
        t1 = _parse_hora(entradas[i])
        t2 = _parse_hora(saidas[i])
        if t1 and t2 and t2 > t1:
            tempo_trabalhado += datetime.combine(date.today(), t2) - datetime.combine(date.today(), t1)

    # Se sobrou uma Entrada sem Saída e é hoje, calcula parcial até o momento
    hoje_obj = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    if len(entradas) > len(saidas) and data_obj == hoje_obj:
        t1 = _parse_hora(entradas[-1])
        if t1:
            agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
            t_entrada_hoje = datetime.combine(data_obj, t1).replace(tzinfo=ZoneInfo("America/Sao_Paulo"))
            if agora > t_entrada_hoje:
                tempo_trabalhado += agora - t_entrada_hoje

    total_seg = int(tempo_trabalhado.total_seconds())
    horas, mins = divmod(total_seg // 60, 60)
    total_fmt = f"{horas:02d}:{mins:02d}h"

    diferenca_seg = total_seg - carga_seg
    diff_abs = abs(diferenca_seg) // 60
    diff_h, diff_m = divmod(diff_abs, 60)

    if diferenca_seg >= 0:
        diferenca_fmt = f"+{diff_h:02d}:{diff_m:02d}h"
    else:
        diferenca_fmt = f"-{diff_h:02d}:{diff_m:02d}h"

    return {
        "total_trabalhado_seg": total_seg,
        "total_trabalhado_fmt": total_fmt,
        "diferenca_seg": diferenca_seg,
        "diferenca_fmt": diferenca_fmt,
        "is_excedente": diferenca_seg > 0,
        "is_faltante": diferenca_seg < 0,
        "tem_registro": True,
    }

def obter_notificacoes_usuario(user_id):
    """Gera a lista de notificações/banners para o painel do usuário.

    Otimizada para evitar centenas de queries por request:
      - Cache de resultado por 30s (invalidado ao bater ponto).
      - Janela de 30 dias para o cálculo de faltas.
      - Usa o cache de feriados (_carregar_feriados) em vez de consultar o
        banco dia a dia.
    """
    if not user_id:
        return []

    # ── 1. Cache: retorna resultado recente se disponível ──
    cached = _NOTIF_CACHE.get(user_id)
    agora = time.time()
    if cached and (agora - cached["momento"]) < _NOTIF_CACHE_TTL:
        return cached["notifs"]

    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    notificacoes = []

    try:
        # ── 2. Uma única query: todos os pontos do usuário ──
        registros = RegistroPonto.query.filter_by(usuario_id=user_id).all()

        # Agrupa registros por data em memória
        pontos_por_data: dict[date, list] = {}
        primeiro_registro_data = hoje

        for r in registros:
            try:
                d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            except (ValueError, TypeError):
                continue
            pontos_por_data.setdefault(d_obj, []).append(r)
            if d_obj < primeiro_registro_data:
                primeiro_registro_data = d_obj

        # ── 3. Faltas totais (janela de 30 dias) ──
        # Calcula o limite: janela de 30 dias ou primeiro registro/cadastro,
        # o que vier antes.
        usuario_obj = Usuario.query.get(user_id)
        data_inicio = (
            usuario_obj.data_cadastro.date()
            if usuario_obj and usuario_obj.data_cadastro
            else hoje - timedelta(days=NOTIF_JANELA_DIAS)
        )
        limite_busca = max(
            hoje - timedelta(days=NOTIF_JANELA_DIAS),
            min(primeiro_registro_data, data_inicio),
        )

        _, subdiv = _regiao_feriados()
        # Pré-carrega feriados dos anos envolvidos para não reconsultar
        for ano in range(limite_busca.year, hoje.year + 1):
            _carregar_feriados(ano, subdiv)

        faltas_count = 0
        curr = hoje - timedelta(days=1)
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

        # ── 4. Pontos incompletos (apenas janela de 30 dias) ──
        janela_inicio = hoje - timedelta(days=NOTIF_JANELA_DIAS)
        dias_incompletos = 0
        for d_obj, regs_do_dia in pontos_por_data.items():
            if janela_inicio <= d_obj < hoje and eh_dia_util(d_obj):
                if dia_ponto_incompleto(regs_do_dia):
                    dias_incompletos += 1

        if dias_incompletos > 0:
            notificacoes.append({
                "id": "pontos_incompletos",
                "tipo": "warning",
                "titulo": "Pontos Incompletos!",
                "mensagem": f"Você tem {dias_incompletos} dia(s) com batidas de ponto incompletas.",
                "link": url_for("meu_historico"),
            })

        # ── 5. Ponto de hoje (usando registros já carregados, sem query) ──
        if eh_dia_util(hoje):
            tipos_hoje = [p.tipo for p in pontos_por_data.get(hoje, [])]
            if "Entrada" not in tipos_hoje:
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

    # ── 6. Salva no cache ──
    _NOTIF_CACHE[user_id] = {"momento": agora, "notifs": notificacoes}

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

@app.route("/alterar_senha", methods=["POST"])
@login_required
def alterar_senha():
    senha_atual = request.form.get("senha_atual", "")
    nova_senha = request.form.get("nova_senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")

    if not check_password_hash(current_user.senha_hash, senha_atual):
        flash("A senha atual está incorreta.", "danger")
        return redirect(request.referrer or url_for("index"))

    if nova_senha != confirmar_senha:
        flash("A confirmação da nova senha não confere.", "danger")
        return redirect(request.referrer or url_for("index"))

    # Validação completa de senha (mesma regra do cadastro/reset)
    if len(nova_senha) < 8:
        flash("A senha deve ter pelo menos 8 caracteres.", "danger")
        return redirect(request.referrer or url_for("index"))
    if not re.search(r"[A-Z]", nova_senha):
        flash("A senha deve conter pelo menos uma letra maiúscula.", "danger")
        return redirect(request.referrer or url_for("index"))
    if not re.search(r"[a-z]", nova_senha):
        flash("A senha deve conter pelo menos uma letra minúscula.", "danger")
        return redirect(request.referrer or url_for("index"))
    if not re.search(r"\d", nova_senha):
        flash("A senha deve conter pelo menos um número.", "danger")
        return redirect(request.referrer or url_for("index"))
    if not re.search(r"[@#*]", nova_senha):
        flash("A senha deve conter pelo menos um caractere especial (@, # ou *).", "danger")
        return redirect(request.referrer or url_for("index"))

    current_user.senha_hash = generate_password_hash(nova_senha, method="scrypt")
    db.session.commit()
    registrar_log(current_user.id, "Alterou a própria senha")
    flash("Senha alterada com sucesso!", "success")
    return redirect(request.referrer or url_for("index"))


@app.route("/admin/lancar-ponto-manual", methods=["POST"])
@admin_required
def admin_lancar_ponto_manual():
    usuario_id = request.form.get("usuario_id")
    data_raw = request.form.get("data")        # esperada no formato YYYY-MM-DD
    tipo = request.form.get("tipo")
    hora_raw = request.form.get("hora")        # esperada no formato HH:MM
    justificativa = request.form.get("justificativa", "").strip()

    if not usuario_id or not data_raw or not tipo or not hora_raw:
        flash("Todos os campos obrigatórios devem ser preenchidos.", "danger")
        return redirect(request.referrer or url_for("admin"))

    usuario_alvo = Usuario.query.get(usuario_id)
    if not usuario_alvo:
        flash("Usuário não encontrado.", "danger")
        return redirect(request.referrer or url_for("admin"))

    # Formatar data de YYYY-MM-DD para DD/MM/YYYY
    try:
        data_obj = datetime.strptime(data_raw, "%Y-%m-%d")
        data_formatada = data_obj.strftime("%d/%m/%Y")
    except ValueError:
        data_formatada = data_raw

    # Garantir formato HH:MM:SS para hora
    hora_formatada = hora_raw if len(hora_raw) == 8 else f"{hora_raw}:00"

    # Verificar se já existe um registro idêntico para o usuário nessa data e tipo
    ponto_existente = RegistroPonto.query.filter_by(
        usuario_id=usuario_alvo.id,
        data=data_formatada,
        tipo=tipo
    ).first()

    if ponto_existente:
        ponto_existente.hora = hora_formatada
        ponto_existente.foi_ajustado = True
        msg_acao = f"Atualizou o ponto ({tipo}) de {usuario_alvo.nome} para o dia {data_formatada} às {hora_formatada}."
    else:
        novo_ponto = RegistroPonto(
            usuario_id=usuario_alvo.id,
            data=data_formatada,
            tipo=tipo,
            hora=hora_formatada,
            foi_ajustado=True
        )
        db.session.add(novo_ponto)
        msg_acao = f"Lançou manualmente o ponto ({tipo}) de {usuario_alvo.nome} para o dia {data_formatada} às {hora_formatada}."

    db.session.commit()
    _invalidar_notif_cache(int(usuario_alvo.id))

    desc_log = msg_acao
    if justificativa:
        desc_log += f" Justificativa: {justificativa}"
    registrar_log(current_user.id, desc_log, entidade_id=usuario_alvo.id)

    flash(f"Ponto de {usuario_alvo.nome} lançado com sucesso!", "success")
    return redirect(request.referrer or url_for("admin"))

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

    # Horas dos pontos de hoje para o JS recalcular o saldo ao vivo (fuso SP)
    # Lista ordenada de pontos do dia (somente Entrada/Saída)
    lista_pontos_hoje = []
    for p in pontos_hoje_objs:
        tipo = getattr(p, "tipo", "")
        if tipo in PONTOS_PERMITIDOS:
            lista_pontos_hoje.append({"tipo": tipo, "hora": getattr(p, "hora", None)})

    # Próximo ponto a ser batido (Entrada ou Saída) baseado no último do dia
    faltantes_hoje = identificar_pontos_faltantes(pontos_hoje_objs)
    proximo_tipo = faltantes_hoje[0] if faltantes_hoje else "Entrada"

    return render_template(
        "index.html",
        ultimo_ponto=ultimo_ponto,
        data_hoje=data_hoje,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
        pontos_today=lista_pontos_hoje,
        proximo_tipo=proximo_tipo,
        carga_diaria_min=480
    )

@app.route("/registrar/<tipo>", methods=["POST"])
@login_required
def registrar(tipo):
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    data_atual = agora.strftime("%d/%m/%Y")
    hora_atual = agora.strftime("%H:%M:%S")

    # Apenas Entrada e Saída são permitidas; pode bater quantas vezes precisar no dia
    if tipo not in PONTOS_PERMITIDOS:
        flash("Tipo de ponto inválido.", "danger")
        return redirect(url_for("index"))

    # Anti-duplicata: evita duplo-clique - bloqueia QUALQUER ponto criado nos últimos 5s
    # (o frontend também desabilita o botão; esta é a camada de segurança do servidor)
    try:
        threshold = agora - timedelta(seconds=5)
        ultimo = RegistroPonto.query.filter(
            RegistroPonto.usuario_id == current_user.id,
            RegistroPonto.data == data_atual
        ).order_by(RegistroPonto.id.desc()).first()
        if ultimo:
            dup_hora = ultimo.hora
            dup_h, dup_m, dup_s = (int(x) for x in dup_hora.split(":"))
            dup_dt = agora.replace(hour=dup_h, minute=dup_m, second=int(dup_s), microsecond=0)
            if dup_dt >= threshold:
                flash("Ponto já registrado recentemente. Por favor, aguarde.", "warning")
                return redirect(url_for("index"))
    except Exception:
        pass

    novo_ponto = RegistroPonto(
        data=data_atual,
        tipo=tipo,
        hora=hora_atual,
        usuario_id=current_user.id,
        foi_ajustado=False
    )
    db.session.add(novo_ponto)
    db.session.commit()
    _invalidar_notif_cache(current_user.id)

    flash(f"Ponto ({tipo}) registrado às {hora_atual} com sucesso!", "success")
    return redirect(url_for("index"))

@app.route("/registrar/auto", methods=["POST"])
@login_required
def registrar_auto():
    # Registra automaticamente o próximo ponto (Entrada ou Saída) baseado no último
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    data_atual = agora.strftime("%d/%m/%Y")

    registros_hoje = RegistroPonto.query.filter_by(
        usuario_id=current_user.id, data=data_atual
    ).order_by(RegistroPonto.id.asc()).all()

    faltantes = identificar_pontos_faltantes(registros_hoje)
    # Nunca fica sem um próximo ponto: sempre será "Entrada" ou "Saída"
    proximo = faltantes[0] if faltantes else "Entrada"
    hora_atual = agora.strftime("%H:%M:%S")

    # Anti-duplicata: evita duplo-clique - bloqueia QUALQUER ponto criado nos últimos 5s
    try:
        threshold = agora - timedelta(seconds=5)
        ultimo = RegistroPonto.query.filter(
            RegistroPonto.usuario_id == current_user.id,
            RegistroPonto.data == data_atual
        ).order_by(RegistroPonto.id.desc()).first()
        if ultimo:
            dup_hora = ultimo.hora
            dup_h, dup_m, dup_s = (int(x) for x in dup_hora.split(":"))
            dup_dt = agora.replace(hour=dup_h, minute=dup_m, second=int(dup_s), microsecond=0)
            if dup_dt >= threshold:
                flash("Ponto já registrado recentemente. Por favor, aguarde.", "warning")
                return redirect(url_for("index"))
    except Exception:
        pass

    novo_ponto = RegistroPonto(
        data=data_atual,
        tipo=proximo,
        hora=hora_atual,
        usuario_id=current_user.id,
        foi_ajustado=False,
    )
    db.session.add(novo_ponto)
    db.session.commit()
    _invalidar_notif_cache(current_user.id)

    flash(f"Ponto ({proximo}) registrado às {hora_atual} com sucesso!", "success")
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
        
        # Se NÃO for dia útil e NÃO houver registros, pula o dia
        if not eh_dia_util(d_obj) and not registros_do_dia:
            continue

        saldo = calcular_saldo_dia(registros_do_dia, d_obj)

        # No modelo de pares ilimitados, o dia está incompleto quando existe
        # uma Entrada em aberto (sem a Saída correspondente de fechamento),
        # ou quando não houve nenhuma batida no dia.
        incompleto = dia_ponto_incompleto(registros_do_dia) or not registros_do_dia

        historico_analisado.append({
            "data": data_str,
            "registros": registros_do_dia,
            "incompleto": incompleto,
            "saldo": saldo,
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
    dias_registrados = defaultdict(list)
    primeira_data = hoje
    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            if r.tipo in PONTOS_PERMITIDOS:
                dias_registrados[d_obj].append((r.tipo, r.hora))
            if d_obj < primeira_data:
                primeira_data = d_obj
        except ValueError:
            pass

    # Ordena por dia, depois pela ordem de registro (id preserva a ordem cronológica)
    tabela_linhas = [["Dia", "Movimentações", "Total / Status"]]
    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    total_segundos_faltantes = 0
    total_faltas_dias = 0
    FMT = "%H:%M:%S"
    segundos_carga_diaria = int(CARGA_HORARIA_DIARIA.total_seconds())

    curr = primeira_data if registros else hoje
    while curr <= hoje:
        dia_str = curr.strftime("%d/%m/%Y")
        regs = dias_registrados.get(curr, [])

        if regs:
            # Constrói texto de movimentações: "E 08:00 · S 12:00 · E 13:00 · S 18:00"
            mov = []
            entradas = []
            saidas = []
            for tipo, hora in regs:
                if tipo == "Entrada":
                    mov.append(f"E {hora}")
                    entradas.append(hora)
                elif tipo == "Saída":
                    mov.append(f"S {hora}")
                    saidas.append(hora)
            mov_texto = "  ".join(mov)

            tempo_trabalhado = timedelta()
            for i in range(min(len(entradas), len(saidas))):
                t1, t2 = datetime.strptime(entradas[i], FMT), datetime.strptime(saidas[i], FMT)
                if t2 > t1:
                    tempo_trabalhado += t2 - t1

            tot = int(tempo_trabalhado.total_seconds())
            total_segundos_trabalhados += tot

            # Dia encerrado se a última movimentação do dia for uma Saída
            dia_encerrado = bool(regs) and regs[-1][0] == "Saída"
            if curr < hoje or dia_encerrado:
                if tot > segundos_carga_diaria:
                    total_segundos_extras += (tot - segundos_carga_diaria)
                elif eh_dia_util(curr) and tot < segundos_carga_diaria:
                    total_segundos_faltantes += (segundos_carga_diaria - tot)

            hrs, mins = divmod(tot // 60, 60)
            tabela_linhas.append([dia_str, mov_texto, f"{hrs:02d}:{mins:02d}h"])
        elif eh_dia_util(curr):
            if curr < hoje:
                total_faltas_dias += 1
                total_segundos_faltantes += segundos_carga_diaria
                tabela_linhas.append([dia_str, "--:--", "FALTA"])
            else:
                tabela_linhas.append([dia_str, "--:--", "Em Aberto"])
        curr += timedelta(days=1)

    # Exportação baseada no formato
    if formato == "pdf":
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        elementos = []
        estilos = getSampleStyleSheet()
        
        # Cabeçalho
        elementos.append(Paragraph(f"Folha de Ponto - {usuario.nome}", estilos["Heading1"]))
        elementos.append(Paragraph(f"E-mail: {usuario.email} | Emissão: {datetime.now().strftime('%d/%m/%Y às %H:%M')}", estilos["Normal"]))
        elementos.append(Spacer(1, 12))
        
        # Tabela
        tabela = Table(tabela_linhas, repeatRows=1)
        estilo_tabela = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ])
        
        # Estilo para "FALTA"
        for i, row in enumerate(tabela_linhas):
            if "FALTA" in row:
                estilo_tabela.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fdecea'))
                estilo_tabela.add('TEXTCOLOR', (0, i), (-1, i), colors.HexColor('#d9534f'))
        
        tabela.setStyle(estilo_tabela)
        elementos.append(tabela)
        elementos.append(Spacer(1, 12))
        
        # Footer (Totais)
        h_t = total_segundos_trabalhados // 3600
        m_t = (total_segundos_trabalhados % 3600) // 60
        
        h_e = total_segundos_extras // 3600
        m_e = (total_segundos_extras % 3600) // 60
        
        h_f = total_segundos_faltantes // 3600
        m_f = (total_segundos_faltantes % 3600) // 60
        
        balanco = total_segundos_extras - total_segundos_faltantes
        h_b = abs(balanco) // 3600
        m_b = (abs(balanco) % 3600) // 60
        
        elementos.append(Paragraph(f"<b>Horas Totais Trabalhadas:</b> {h_t:02d}:{m_t:02d}h", estilos["Normal"]))
        elementos.append(Paragraph(f"<b>(+) Total Horas Extras:</b> <font color='green'>{h_e:02d}:{m_e:02d}h</font>", estilos["Normal"]))
        elementos.append(Paragraph(f"<b>(-) Total Horas Faltantes:</b> <font color='red'>{h_f:02d}:{m_f:02d}h ({total_faltas_dias} dia(s) ausente)</font>", estilos["Normal"]))
        
        cor_balanco = 'red' if balanco < 0 else 'green'
        texto_balanco = f"BALANÇO FINAL (BANCO DE HORAS): <font color='{cor_balanco}'>{'-' if balanco < 0 else ''}{h_b:02d}:{m_b:02d}h ({'A Repor' if balanco < 0 else 'Crédito'})</font>"
        
        elementos.append(Paragraph(f"<b>{texto_balanco}</b>", estilos["Normal"]))
        
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
#   ROTAS DE UPLOAD, DEPARTAMENTOS & RBAC
# ==========================================
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'perfil')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/perfil/upload-foto", methods=["POST"])
@login_required
def upload_foto_perfil():
    if 'foto' not in request.files:
        flash("Nenhum arquivo enviado.", "warning")
        return redirect(request.referrer or url_for("index"))
    
    file = request.files['foto']
    if file.filename == '':
        flash("Nenhum arquivo selecionado.", "warning")
        return redirect(request.referrer or url_for("index"))
    
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"user_{current_user.id}_{secrets.token_hex(8)}.{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        # Remove foto antiga se existir
        if current_user.foto_url:
            old_path = os.path.join(app.root_path, current_user.foto_url.lstrip('/'))
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except Exception:
                    pass
        
        current_user.foto_url = f"/static/uploads/perfil/{filename}"
        db.session.commit()
        registrar_log(current_user.id, "Atualizou foto de perfil")
        flash("Foto de perfil atualizada com sucesso!", "success")
    else:
        flash("Formato de imagem inválido (use PNG, JPG ou JPEG).", "danger")

    return redirect(request.referrer or url_for("index"))

@app.route("/admin/departamentos", methods=["GET", "POST"])
@login_required
@admin_required
def gerenciar_departamentos():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        descricao = request.form.get("descricao", "").strip()
        if not nome:
            flash("Nome do departamento é obrigatório.", "warning")
        elif Departamento.query.filter_by(nome=nome).first():
            flash(f"Departamento '{nome}' já existe.", "warning")
        else:
            dep = Departamento(nome=nome, descricao=descricao)
            db.session.add(dep)
            db.session.commit()
            registrar_log(current_user.id, f"Criou o departamento '{nome}'")
            flash(f"Departamento '{nome}' cadastrado com sucesso!", "success")
        return redirect(url_for("admin_usuarios"))

    deps = Departamento.query.order_by(Departamento.nome.asc()).all()
    return render_template("admin_fragment_departamentos.html", departamentos=deps)

@app.route("/admin/departamentos/excluir/<int:id>", methods=["POST"])
@login_required
@admin_required
def excluir_departamento(id):
    dep = Departamento.query.get_or_404(id)
    nome_dep = dep.nome
    # Desvincular usuários do departamento excluído
    Usuario.query.filter_by(departamento_id=id).update({"departamento_id": None})
    db.session.delete(dep)
    db.session.commit()
    registrar_log(current_user.id, f"Excluiu departamento '{nome_dep}'")
    flash(f"Departamento '{nome_dep}' excluído com sucesso!", "success")
    return redirect(url_for("admin_usuarios"))

@app.route("/admin/usuarios/<int:user_id>/atualizar", methods=["POST"])
@login_required
@admin_required
def atualizar_usuario_admin(user_id):
    user = Usuario.query.get_or_404(user_id)
    departamento_id = request.form.get("departamento_id")
    
    if departamento_id == "" or departamento_id == "none":
        user.departamento_id = None
    elif departamento_id:
        user.departamento_id = int(departamento_id)
    
    # Atualizar Permissões Granulares (RBAC)
    import json
    permissoes = {
        "pode_ver_dashboard": request.form.get("pode_ver_dashboard") == "on",
        "pode_ver_historico": request.form.get("pode_ver_historico") == "on",
        "pode_lancar_ponto_manual": request.form.get("pode_lancar_ponto_manual") == "on",
        "pode_aprovar_solicitacoes": request.form.get("pode_aprovar_solicitacoes") == "on",
        "pode_exportar_relatorios": request.form.get("pode_exportar_relatorios") == "on",
        "pode_gerenciar_feriados": request.form.get("pode_gerenciar_feriados") == "on",
    }
    user.permissoes = json.dumps(permissoes)
    db.session.commit()
    registrar_log(current_user.id, f"Atualizou departamento e permissões do usuário {user.nome}", user_id)
    flash(f"Dados e permissões do colaborador {user.nome} salvos com sucesso!", "success")
    return redirect(url_for("admin_usuarios"))

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
    if "departamentos" not in context:
        context["departamentos"] = Departamento.query.order_by(Departamento.nome.asc()).all()
    regiao_uf, regiao_cidade, regiao_fonte = _regiao_display()
    if "regiao_uf" not in context:
        context["regiao_uf"] = regiao_uf
    if "regiao_cidade" not in context:
        context["regiao_cidade"] = regiao_cidade
    if "regiao_fonte" not in context:
        context["regiao_fonte"] = regiao_fonte
    if "ufs_brasil" not in context:
        context["ufs_brasil"] = UFS_BRASIL
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
    # Garante feriados automáticos (nacionais + regionais) presentes no banco
    _sincronizar_feriados_lib()
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
        dados_semana=dados_semana,
        feriados=_feriados_do_mes(hoje)
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
        
        # Garante feriados automáticos (nacionais + regionais) presentes no banco
        _sincronizar_feriados_lib()

        # Feriados do mês atual
        feriados = _feriados_do_mes(hoje)
        
        # Calcular Banco de Horas por usuário
        usuarios_banco_horas = []
        for u in usuarios:
            registros_user = RegistroPonto.query.filter_by(usuario_id=u.id).all()
            
            dias_registrados = defaultdict(list)
            for r in registros_user:
                try:
                    d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
                    if r.tipo in PONTOS_PERMITIDOS:
                        dias_registrados[d_obj].append((r.tipo, r.hora))
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
                regs = dias_registrados.get(curr, [])
                if regs:
                    entradas = [h for t, h in regs if t == "Entrada"]
                    saidas = [h for t, h in regs if t == "Saída"]
                    tempo_trabalhado = timedelta()
                    for i in range(min(len(entradas), len(saidas))):
                        t1, t2 = datetime.strptime(entradas[i], FMT), datetime.strptime(saidas[i], FMT)
                        if t2 > t1:
                            tempo_trabalhado += t2 - t1
                    tot = int(tempo_trabalhado.total_seconds())
                    total_segundos_trabalhados += tot
                    dia_encerrado = bool(regs) and regs[-1][0] == "Saída"
                    if curr < hoje or dia_encerrado:
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

        regiao_uf, regiao_cidade, regiao_fonte = _regiao_display()

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
            data_hoje=hoje,
            regiao_uf=regiao_uf,
            regiao_cidade=regiao_cidade,
            regiao_fonte=regiao_fonte,
            ufs_brasil=UFS_BRASIL,
        )

    if view_name == "usuarios":
        usuarios = Usuario.query.all()
        departamentos = Departamento.query.order_by(Departamento.nome.asc()).all()
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
        return render_template("admin_fragment_usuarios.html", usuarios=usuarios, departamentos=departamentos, total_solicitacoes_pendentes=total_solicitacoes_pendentes)

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
    _invalidar_notif_cache(solicitacao.usuario_id)
    return redirect(url_for("admin_solicitacoes"))

@app.route("/admin/usuarios")
@login_required
@admin_required
def admin_usuarios():
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("index"))

    usuarios = Usuario.query.all()
    departamentos = Departamento.query.order_by(Departamento.nome.asc()).all()
    total_solicitacoes_pendentes = 0
    try:
        total_solicitacoes_pendentes = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    except Exception:
        pass

    return render_admin_shell(
        initial_view="usuarios",
        usuarios=usuarios,
        departamentos=departamentos,
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
        _invalidar_notif_cache(user_id)
        
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

    dias_registrados = defaultdict(list)
    primeira_data = hoje

    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            if r.tipo in PONTOS_PERMITIDOS:
                dias_registrados[d_obj].append((r.tipo, r.hora))
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

    tabela_linhas = [["Dia", "Movimentações", "Total / Status"]]

    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    total_segundos_faltantes = 0
    total_faltas_dias = 0

    FMT = "%H:%M:%S"
    segundos_carga_diaria = int(CARGA_HORARIA_DIARIA.total_seconds())

    curr = primeira_data
    while curr <= hoje:
        dia_str = curr.strftime("%d/%m/%Y")
        regs = dias_registrados.get(curr, [])

        if regs:
            mov = []
            entradas = []
            saidas = []
            for tipo, hora in regs:
                if tipo == "Entrada":
                    mov.append(f"E {hora}")
                    entradas.append(hora)
                elif tipo == "Saída":
                    mov.append(f"S {hora}")
                    saidas.append(hora)
            mov_texto = "  ".join(mov)

            tempo_trabalhado = timedelta()
            for i in range(min(len(entradas), len(saidas))):
                t1, t2 = datetime.strptime(entradas[i], FMT), datetime.strptime(saidas[i], FMT)
                if t2 > t1:
                    tempo_trabalhado += t2 - t1

            tot = int(tempo_trabalhado.total_seconds())
            total_segundos_trabalhados += tot

            # Dia encerrado se a última movimentação do dia for uma Saída
            dia_encerrado = bool(regs) and regs[-1][0] == "Saída"
            if curr < hoje or dia_encerrado:
                if tot > segundos_carga_diaria:
                    total_segundos_extras += (tot - segundos_carga_diaria)
                elif eh_dia_util(curr) and tot < segundos_carga_diaria:
                    total_segundos_faltantes += (segundos_carga_diaria - tot)

            hrs, mins = divmod(tot // 60, 60)
            tabela_linhas.append([dia_str, mov_texto, f"{hrs:02d}:{mins:02d}h"])

        elif eh_dia_util(curr):
            if curr < hoje:
                total_faltas_dias += 1
                total_segundos_faltantes += segundos_carga_diaria
                tabela_linhas.append([dia_str, "--:--", "FALTA"])
            else:
                tabela_linhas.append([dia_str, "--:--", "Em Aberto"])

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

    tabela = Table(tabela_linhas, colWidths=[80, 300, 90])
    estilo_tabela = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ]
    for i, linha in enumerate(tabela_linhas[1:], start=1):
        if linha[2] == "FALTA":
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
        feriado = Feriado(data=data, descricao=descricao, fonte="manual")
        db.session.add(feriado)
        # Se o admin readicionou manualmente, deixa de ser "ignorado"
        db.session.query(FeriadoIgnorado).filter_by(data=data).delete()
        db.session.commit()
        _FERIADOS_CACHE.clear()
        flash("Feriado cadastrado com sucesso!", "success")
    except Exception as e:
        flash(f"Erro ao cadastrar feriado: {e}", "danger")
    return redirect(url_for("admin_panel"))

@app.route("/admin/feriados/excluir/<int:id>", methods=["POST"])
@login_required
@admin_required
def excluir_feriado(id):
    feriado = Feriado.query.get_or_404(id)
    data_feriado = feriado.data
    db.session.delete(feriado)
    # Marca como ignorado para o sync automático não readicionar
    db.session.add(FeriadoIgnorado(data=data_feriado))
    db.session.commit()
    _FERIADOS_CACHE.clear()
    flash("Feriado excluído com sucesso!", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/feriados/sincronizar", methods=["POST"])
@login_required
@admin_required
def sincronizar_feriados():
    """Dispara manualmente a sincronização dos feriados da biblioteca
    (nacionais + os da UF da região configurada)."""
    try:
        inseridos = _sincronizar_feriados_lib()
        if inseridos:
            flash(f"Sincronização concluída: {inseridos} feriado(s) adicionado(s).", "success")
        else:
            flash("Sincronização concluída: nenhum feriado novo encontrado.", "info")
    except Exception as e:
        flash(f"Erro ao sincronizar feriados: {e}", "danger")
    return redirect(url_for("admin_panel"))

@app.route("/api/localizacao", methods=["POST"])
@login_required
@admin_required
def api_localizacao():
    """Recebe as coordenadas do navegador do admin, resolve a UF/cidade via
    reverse geocode (BigDataCloud) e passa a usar essa região nos feriados
    do sistema (configuração global e persistida). As coordenadas em si não
    são armazenadas — apenas a UF e a cidade resultantes."""
    try:
        dados = request.get_json(silent=True) or {}
        lat = float(dados.get("lat"))
        lng = float(dados.get("lng"))
    except (TypeError, ValueError):
        return jsonify(status="erro", msg="Coordenadas inválidas."), 400

    if not (-90 <= lat <= 90) or not (-180 <= lng <= 180):
        return jsonify(status="erro", msg="Coordenadas fora dos limites válidos."), 400

    uf, cidade = _reverse_geocode(lat, lng)
    if not uf:
        return jsonify(
            status="erro",
            msg="Não foi possível identificar a região (ponto fora do Brasil ou serviço de localização indisponível).",
        ), 422

    try:
        _set_config("uf_feriado", uf)
        _set_config("cidade_feriado", cidade)
        _set_config("regiao_fonte", "geo")
        db.session.commit()
        _invalidar_cache_regiao()
        _sincronizar_feriados_lib()
    except Exception as e:
        db.session.rollback()
        return jsonify(status="erro", msg=f"Falha ao salvar a região: {e}"), 500

    return jsonify(status="ok", uf=uf, cidade=cidade)

@app.route("/admin/feriados/regiao", methods=["POST"])
@login_required
@admin_required
def definir_regiao_feriados():
    """Define manualmente a região (UF ou 'BR') usada nos feriados do sistema."""
    uf = (request.form.get("uf") or "").strip().upper()

    if uf == "BR":
        # Remove a configuração -> volta para ESTADO_FERIADO (ou somente nacional)
        for chave in ("uf_feriado", "cidade_feriado", "regiao_fonte"):
            reg = Configuracao.query.get(chave)
            if reg is not None:
                db.session.delete(reg)
        db.session.commit()
        _invalidar_cache_regiao()
        _sincronizar_feriados_lib()
        flash("Feriados regionais definidos como nacionais (BR).", "success")
        return redirect(url_for("admin_panel"))

    if uf not in UFS_BRASIL:
        flash("Sigla de UF inválida.", "danger")
        return redirect(url_for("admin_panel"))

    try:
        _set_config("uf_feriado", uf)
        _set_config("regiao_fonte", "manual")
        # Remove a cidade (não faz sentido para definição manual por UF)
        reg_cidade = Configuracao.query.get("cidade_feriado")
        if reg_cidade is not None:
            db.session.delete(reg_cidade)
        db.session.commit()
        _invalidar_cache_regiao()
        _sincronizar_feriados_lib()
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao definir a região: {e}", "danger")
        return redirect(url_for("admin_panel"))

    flash(f"Feriados regionais definidos para {uf} ({UFS_BRASIL[uf]}).", "success")
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
