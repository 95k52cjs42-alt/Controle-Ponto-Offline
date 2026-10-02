import io
import os
import re
import time
import hashlib
import html
import secrets
import threading
import click
import holidays
import calendar

from collections import defaultdict, deque
from datetime import datetime, timedelta, date
from functools import wraps
from urllib.parse import parse_qsl, urlencode, urlsplit
from zoneinfo import ZoneInfo
from xml.sax.saxutils import escape as xml_escape

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
    send_from_directory,
    url_for,
    make_response,
    session,
    abort,
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
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image, ImageOps, UnidentifiedImageError
from dotenv import load_dotenv
import resend
import dns.resolver

# Bibliotecas para a geração do PDF (ReportLab)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

load_dotenv()


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "sim"}


def _env_list(name, default=None):
    raw = os.environ.get(name)
    if raw is None:
        return list(default or [])
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _normalise_public_base_url(value):
    value = (value or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError("PUBLIC_BASE_URL deve ser uma URL HTTP/HTTPS absoluta sem credenciais.")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise RuntimeError("PUBLIC_BASE_URL deve conter somente esquema, host e porta.")
    return value


# A aplicação não possui segredo de fallback. O teste injeta uma chave própria
# antes da importação deste módulo.
TESTING = _env_bool("TESTING")
APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")).strip().lower()
IS_PRODUCTION = APP_ENV not in {"development", "dev", "test", "testing", "local"}
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY ausente: configure uma chave aleatória antes de iniciar.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    TESTING=TESTING,
    DEBUG=False,
    MAX_CONTENT_LENGTH=3 * 1024 * 1024,
    MAX_FORM_MEMORY_SIZE=256 * 1024,
    MAX_FORM_PARTS=50,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_REFRESH_EACH_REQUEST=False,
    REMEMBER_COOKIE_DURATION=timedelta(hours=8),
    WTF_CSRF_ENABLED=True,
    PREFERRED_URL_SCHEME="http",
)
if APP_ENV == "development" and _env_bool("FLASK_DEBUG", False):
    app.config["DEBUG"] = True
if IS_PRODUCTION and _env_bool("FLASK_DEBUG", False):
    raise RuntimeError("FLASK_DEBUG não pode ser habilitado em produção.")
if IS_PRODUCTION and app.config["DEBUG"]:
    raise RuntimeError("Debug não pode ser habilitado em produção.")

# Links de e-mail são sempre baseados nesta URL, nunca no Host/Referer.
if IS_PRODUCTION and len(SECRET_KEY) < 32:
    raise RuntimeError("Produção exige SECRET_KEY com pelo menos 32 caracteres.")
public_base_url = _normalise_public_base_url(os.environ.get("PUBLIC_BASE_URL", ""))
if not public_base_url:
    if IS_PRODUCTION:
        raise RuntimeError("PUBLIC_BASE_URL ausente: configure a URL pública da aplicação.")
    public_base_url = "http://localhost:5000"
app.config["PUBLIC_BASE_URL"] = public_base_url
app.config["PREFERRED_URL_SCHEME"] = urlsplit(public_base_url).scheme or "https"

trusted_hosts = _env_list("TRUSTED_HOSTS")
if not trusted_hosts:
    if IS_PRODUCTION:
        raise RuntimeError("TRUSTED_HOSTS ausente: configure os hosts públicos permitidos.")
    trusted_hosts = ["localhost", "127.0.0.1"]
base_host = urlsplit(public_base_url).netloc
trusted_hosts = list(dict.fromkeys(trusted_hosts + [base_host, urlsplit(public_base_url).hostname]))
if "*" in trusted_hosts:
    raise RuntimeError("TRUSTED_HOSTS não pode conter '*'.")
app.config["TRUSTED_HOSTS"] = trusted_hosts

if IS_PRODUCTION and urlsplit(public_base_url).scheme != "https":
    raise RuntimeError("Produção exige PUBLIC_BASE_URL com HTTPS.")
cookie_secure = _env_bool("COOKIE_SECURE", public_base_url.startswith("https://"))
if IS_PRODUCTION and not cookie_secure:
    raise RuntimeError("Produção exige COOKIE_SECURE=true (HTTPS).")
app.config["SESSION_COOKIE_SECURE"] = cookie_secure
app.config["REMEMBER_COOKIE_SECURE"] = cookie_secure
app.config["TRUST_PROXY_HEADERS"] = _env_bool("TRUST_PROXY_HEADERS", False)
if app.config["TRUST_PROXY_HEADERS"]:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

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
# O pool de arquivos do SQLite não aceita estes argumentos; isso também permite
# importar a aplicação com uma configuração de teste isolada.
if DATABASE_URL.startswith("sqlite"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
else:
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
auto_init_db = _env_bool("AUTO_INIT_DB", not IS_PRODUCTION and not app.config.get("TESTING", False))
if IS_PRODUCTION and auto_init_db:
    raise RuntimeError("AUTO_INIT_DB deve ser false em produção; use o comando init-db no deploy.")
app.config["AUTO_INIT_DB"] = auto_init_db
app.config["UPLOAD_FOLDER"] = os.path.abspath(os.environ.get("UPLOAD_DIR", os.path.join(app.root_path, "static", "uploads", "perfil")))
app.config["UPLOAD_MAX_BYTES"] = 2 * 1024 * 1024
app.config["UPLOAD_MAX_DIMENSION"] = 4096
app.config["UPLOAD_MAX_PIXELS"] = 16_000_000
app.config["RESET_TOKEN_TTL_SECONDS"] = 30 * 60
app.config["INVITE_TOKEN_TTL_SECONDS"] = 24 * 60 * 60
app.config["CONFIRM_TOKEN_TTL_SECONDS"] = 24 * 60 * 60
app.config["RATE_LIMIT_ENABLED"] = _env_bool("RATE_LIMIT_ENABLED", True)
app.config["RATE_LIMITS"] = {
    "login": (10, 300),
    "forgot_password": (5, 900),
    "cadastro": (5, 900),
    "upload": (10, 900),
    "reset_password": (10, 900),
    "definir_senha_usuario": (10, 900),
    "confirm_email": (10, 900),
    "api_localizacao": (30, 900),
}
app.config["CSRF_FIELD_NAME"] = "_csrf_token"
app.config["CSRF_HEADER_NAME"] = "X-CSRF-Token"
app.config["MAIL_FROM"] = os.environ.get("MAIL_FROM", "onboarding@resend.dev")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"

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

# Rate limit de processo simples. Em produção com múltiplos workers, deve-se
# usar um armazenamento compartilhado (Redis) no proxy/WAF; esta camada protege
# cada processo e não pretende sustituir esse controle de infraestrutura.
_RATE_BUCKETS = {}
_RATE_LIMIT_LOCK = threading.Lock()

# API de reverse geocoding gratuita e sem chave (BigDataCloud)
BIGDATACLOUD_URL = "https://api.bigdatacloud.net/data/reverse-geocode-client"


def _get_config(chave, default=None):
    """Lê um valor da tabela de configurações (None se ausente)."""
    try:
        reg = db.session.get(Configuracao, chave)
        return reg.valor if reg is not None else default
    except Exception:
        return default


def _set_config(chave, valor):
    """Grava/atualiza um valor na tabela de configurações."""
    reg = db.session.get(Configuracao, chave)
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


def _calcular_5o_dia_util_mes(ano, mes):
    """Retorna a data do 5º dia útil do mês informado.

    Usada para decidir quando parar de notificar sobre meses anteriores:
    após o 5º dia útil, o mês anterior é considerado ``fechado`` e as
    notificações de faltas/pontos incompletos não devem mais incluí-lo.
    """
    candidato = date(ano, mes, 1)
    contador = 0
    while True:
        if eh_dia_util(candidato):
            contador += 1
            if contador == 5:
                return candidato
        candidato += timedelta(days=1)


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
        local, dominio = email.strip().lower().rsplit("@", 1)
        if not local or not dominio or "." not in dominio:
            return False
        return len(dns.resolver.resolve(dominio, "MX")) > 0
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
    auth_version = db.Column(db.Integer, nullable=False, default=0)
    foto_url = db.Column(db.String(255), nullable=True)
    departamento_id = db.Column(db.Integer, db.ForeignKey('departamento.id'), nullable=True)
    tipo_contrato = db.Column(db.String(10), nullable=False, default="CLT")
    permissoes = db.Column(db.Text, nullable=True) # Guarda JSON ex: {"pode_ver_dashboard": true, ...}
    data_cadastro = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    pontos = db.relationship("RegistroPonto", backref="usuario", lazy=True)
    solicitacoes = db.relationship("SolicitacaoCorrecao", backref="usuario", lazy=True)
    security_tokens = db.relationship("SecurityToken", back_populates="usuario", lazy=True, cascade="all, delete-orphan")

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

    def get_reset_token(self, expires_sec=None):
        return issue_security_token(self.id, SecurityToken.PURPOSE_RESET, expires_sec or app.config["RESET_TOKEN_TTL_SECONDS"])[0]

    @staticmethod
    def verify_reset_token(token):
        return peek_security_token(token, SecurityToken.PURPOSE_RESET)

    def get_confirmation_token(self, expires_sec=None):
        return issue_security_token(self.id, SecurityToken.PURPOSE_CONFIRM, expires_sec or app.config["CONFIRM_TOKEN_TTL_SECONDS"])[0]

    @staticmethod
    def verify_confirmation_token(token):
        return peek_security_token(token, SecurityToken.PURPOSE_CONFIRM)

class SecurityToken(db.Model):
    """Tokens opacos de uso único; somente o digest é persistido."""
    __tablename__ = "security_token"
    PURPOSE_RESET = "reset"
    PURPOSE_INVITE = "invite"
    PURPOSE_CONFIRM = "confirm"

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    nome = db.Column(db.String(100), nullable=True)
    senha_hash = db.Column(db.String(200), nullable=True)
    purpose = db.Column(db.String(20), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    expira_em = db.Column(db.DateTime, nullable=False)
    usado_em = db.Column(db.DateTime, nullable=True)
    criado_em = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

    usuario = db.relationship("Usuario", back_populates="security_tokens", foreign_keys=[usuario_id])


def _local_now():
    # Colunas DateTime sem timezone; mantemos o mesmo formato em SQLite/PostgreSQL.
    return datetime.now(ZoneInfo("America/Sao_Paulo")).replace(tzinfo=None)


def _token_digest(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_security_token(usuario_id, purpose, ttl_seconds, *, email=None, nome=None, senha_hash=None):
    """Cria um token opaco, aleatório, expirável e de uso único."""
    if purpose not in {SecurityToken.PURPOSE_RESET, SecurityToken.PURPOSE_INVITE, SecurityToken.PURPOSE_CONFIRM}:
        raise ValueError("purpose de token inválido")
    raw_token = secrets.token_urlsafe(48)
    agora = _local_now()
    if usuario_id is not None:
        SecurityToken.query.filter_by(
            usuario_id=usuario_id,
            purpose=purpose,
            usado_em=None,
        ).update({"usado_em": agora}, synchronize_session=False)
    elif email:
        SecurityToken.query.filter_by(
            email=email,
            purpose=purpose,
            usado_em=None,
        ).update({"usado_em": agora}, synchronize_session=False)
    row = SecurityToken(
        usuario_id=usuario_id,
        email=email,
        nome=nome,
        senha_hash=senha_hash,
        purpose=purpose,
        token_hash=_token_digest(raw_token),
        expira_em=agora + timedelta(seconds=int(ttl_seconds)),
    )
    db.session.add(row)
    db.session.commit()
    return raw_token, row


def _get_valid_security_token(raw_token, purpose):
    if not raw_token or not isinstance(raw_token, str):
        return None
    if len(raw_token) < 40 or len(raw_token) > 200:
        return None
    return SecurityToken.query.filter_by(
        token_hash=_token_digest(raw_token),
        purpose=purpose,
        usado_em=None,
    ).filter(SecurityToken.expira_em > _local_now()).first()


def peek_security_token(raw_token, purpose):
    row = _get_valid_security_token(raw_token, purpose)
    return row.usuario if row and row.usuario_id else None


def consume_security_token(raw_token, purpose):
    """Consome atomicamente um token; segunda tentativa devolve None."""
    row = _get_valid_security_token(raw_token, purpose)
    if not row:
        return None
    agora = _local_now()
    updated = SecurityToken.query.filter(
        SecurityToken.id == row.id,
        SecurityToken.usado_em.is_(None),
        SecurityToken.expira_em > agora,
    ).update({"usado_em": agora}, synchronize_session=False)
    db.session.commit()
    return row if updated == 1 else None


def revoke_user_sessions(usuario):
    usuario.auth_version = int(usuario.auth_version or 0) + 1
    db.session.add(usuario)
    db.session.commit()


def _email_link(endpoint, **values):
    return f"{app.config['PUBLIC_BASE_URL']}{url_for(endpoint, **values)}"


def _email_link_html(link, label="Clique no link abaixo"):
    safe_link = html.escape(link, quote=True)
    safe_label = html.escape(label)
    return f'<p><a href="{safe_link}">{safe_label}</a></p>'


def _send_email(to, subject, body):
    try:
        resend.Emails.send({
            "from": app.config["MAIL_FROM"],
            "to": to,
            "subject": subject,
            "html": body,
        })
        return True
    except Exception as exc:
        app.logger.warning("Falha ao enviar e-mail para %s: %s", to, exc)
        return False


DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(24), method="scrypt")


def _password_problem(senha):
    senha = senha or ""
    if len(senha) < 8:
        return "A senha deve ter pelo menos 8 caracteres."
    if not re.search(r"[A-Z]", senha):
        return "A senha deve conter pelo menos uma letra maiúscula."
    if not re.search(r"[a-z]", senha):
        return "A senha deve conter pelo menos uma letra minúscula."
    if not re.search(r"\d", senha):
        return "A senha deve conter pelo menos um número."
    if not re.search(r"[@#*]", senha):
        return "A senha deve conter pelo menos um caractere especial (@, # ou *)."
    return None


def _neutralise_export_value(value):
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r", "\n", " ")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _safe_export_rows(rows):
    return [[_neutralise_export_value(value) for value in row] for row in rows]


def _pdf_text(value):
    return xml_escape(str(value or ""), {'"': '&quot;', "'": '&apos;'})


def _safe_reportlab_image_path(image_path):
    """Valida se o caminho de imagem existe dentro do diretório UPLOAD_FOLDER permitido."""
    if not image_path or not isinstance(image_path, str):
        return None
    upload_dir = os.path.realpath(os.path.abspath(app.config["UPLOAD_FOLDER"]))
    resolved = os.path.realpath(os.path.abspath(image_path))
    if not resolved.startswith(upload_dir + os.sep) or not os.path.isfile(resolved):
        return None
    return resolved


def _validate_profile_image(stream):
    """Valida conteúdo/dimensões e regrava a imagem sem metadados arbitrários."""
    position = stream.tell()
    try:
        stream.seek(0)
        max_bytes = app.config["UPLOAD_MAX_BYTES"]
        data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("A imagem excede o tamanho máximo de 2 MB.")
        with Image.open(io.BytesIO(data)) as image:
            if image.format not in {"PNG", "JPEG", "GIF"}:
                raise ValueError("Formato de imagem inválido.")
            width, height = image.size
            max_dimension = app.config["UPLOAD_MAX_DIMENSION"]
            if width < 1 or height < 1 or width > max_dimension or height > max_dimension:
                raise ValueError("Dimensões da imagem inválidas.")
            if width * height > app.config["UPLOAD_MAX_PIXELS"]:
                raise ValueError("A imagem possui pixels demais.")
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            safe_image = ImageOps.exif_transpose(image)
            if image.format == "PNG":
                safe_image = safe_image.convert("RGBA")
                output_format = "PNG"
            elif image.format == "GIF":
                safe_image = safe_image.convert("P")
                output_format = "GIF"
            else:
                safe_image = safe_image.convert("RGB")
                output_format = "JPEG"
            output = io.BytesIO()
            safe_image.save(output, format=output_format)
        stream.seek(0)
        stream.truncate()
        stream.write(output.getvalue())
        stream.seek(0)
        return output_format
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise ValueError("Arquivo de imagem inválido ou corrompido.") from exc
    finally:
        try:
            stream.seek(position)
        except (OSError, ValueError):
            pass


def _internal_path(candidate, fallback):
    if not candidate:
        return fallback
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return fallback
    if "\\" in candidate or any(ord(char) < 32 for char in candidate):
        return fallback
    return candidate


def _internal_referrer_path(fallback):
    if not request.referrer:
        return fallback
    parsed = urlsplit(request.referrer)
    if parsed.scheme in {"http", "https"}:
        allowed = {urlsplit(app.config["PUBLIC_BASE_URL"]).netloc}
        allowed.update(app.config["TRUSTED_HOSTS"])
        if parsed.netloc not in allowed:
            return fallback
        candidate = parsed.path
        if parsed.query:
            candidate += f"?{parsed.query}"
        return _internal_path(candidate, fallback)
    elif parsed.netloc:
        return fallback
    return _internal_path(request.referrer, fallback)


def _rate_limit(name):
    if not app.config.get("RATE_LIMIT_ENABLED", True):
        return
    limit, window = app.config["RATE_LIMITS"].get(name, (10, 300))
    key = (name, request.remote_addr or "unknown")
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        bucket = _RATE_BUCKETS.setdefault(key, deque())
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= limit:
            abort(429, description="Muitas tentativas. Aguarde antes de tentar novamente.")
        bucket.append(now)


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _csrf_is_valid():
    expected = session.get("_csrf_token")
    supplied = request.form.get(app.config["CSRF_FIELD_NAME"])
    if not supplied:
        supplied = request.headers.get(app.config["CSRF_HEADER_NAME"])
    if not supplied and request.is_json:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            supplied = payload.get(app.config["CSRF_FIELD_NAME"])
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


@app.before_request
def enforce_csrf_and_rate_limits():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _csrf_is_valid():
            abort(403, description="Token CSRF inválido ou ausente.")
    rate_endpoint = request.endpoint
    if rate_endpoint in {
        "login", "cadastro", "forgot_password", "upload_foto_perfil", "reset_password",
        "definir_senha_usuario", "confirm_email", "api_localizacao",
    }:
        _rate_limit("upload" if rate_endpoint == "upload_foto_perfil" else rate_endpoint)


@app.context_processor
def inject_security_context():
    return {"csrf_token": csrf_token}


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(self)")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; connect-src 'self' https://api.bigdatacloud.net",
    )
    if app.config["SESSION_COOKIE_SECURE"] and request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.endpoint in {
        "login", "cadastro", "forgot_password", "reset_password", "definir_senha_usuario",
        "confirm_email", "logout", "redefinir_senha_forca", "alterar_senha",
    }:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify(erro="Requisição excede o limite permitido."), 413
    return "Requisição excede o limite permitido.", 413


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
    hora_original = db.Column(db.String(8), nullable=True)   # HH:MM:SS – hora registrada (para localizar o registro específico)
    hora_correta = db.Column(db.String(8), nullable=False)
    justificativa = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Pendente")
    data_solicitacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(Usuario, int(user_id))
    if not user:
        return None
    # Cookies antigos, sem versão, ou de uma versão revogada não carregam mais
    # o usuário. A rotação de versão ocorre ao redefinir/alterar senha.
    if session.get("_auth_version") != int(user.auth_version or 0):
        return None
    return user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acesso permitido apenas para administradores.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

# Migração leve executada apenas fora do perfil de teste. O bloco antigo que
# criava/migrava o banco durante a importação foi removido deliberadamente.
def _apply_database_migrations():
    """Cria tabelas novas e adiciona colunas em instalações legadas."""
    from sqlalchemy import inspect, text
    db.create_all()
    inspector = inspect(db.engine)
    colunas_usuario = [c["name"] for c in inspector.get_columns("usuario")]
    migrations = (
        ("is_admin", "ALTER TABLE usuario ADD COLUMN is_admin BOOLEAN DEFAULT FALSE"),
        ("email_confirmado", "ALTER TABLE usuario ADD COLUMN email_confirmado BOOLEAN DEFAULT FALSE"),
        ("precisa_redefinir_senha", "ALTER TABLE usuario ADD COLUMN precisa_redefinir_senha BOOLEAN DEFAULT FALSE"),
        ("auth_version", "ALTER TABLE usuario ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0"),
        ("foto_url", "ALTER TABLE usuario ADD COLUMN foto_url VARCHAR(255)"),
        ("departamento_id", "ALTER TABLE usuario ADD COLUMN departamento_id INTEGER"),
        ("permissoes", "ALTER TABLE usuario ADD COLUMN permissoes TEXT"),
        ("tipo_contrato", "ALTER TABLE usuario ADD COLUMN tipo_contrato VARCHAR(10) DEFAULT 'CLT'"),
    )
    for column, statement in migrations:
        if column not in colunas_usuario:
            db.session.execute(text(statement))
    if "data_cadastro" not in colunas_usuario:
        data_type = "TIMESTAMP" if db.engine.name == "postgresql" else "DATETIME"
        db.session.execute(text(f"ALTER TABLE usuario ADD COLUMN data_cadastro {data_type}"))
        db.session.execute(text("UPDATE usuario SET data_cadastro = CURRENT_TIMESTAMP"))

    colunas_ponto = [c["name"] for c in inspector.get_columns("registro_ponto")]
    if "foi_ajustado" not in colunas_ponto:
        db.session.execute(text("ALTER TABLE registro_ponto ADD COLUMN foi_ajustado BOOLEAN DEFAULT FALSE"))
    colunas_solicitacao = [c["name"] for c in inspector.get_columns("solicitacao_correcao")]
    if "hora_original" not in colunas_solicitacao:
        db.session.execute(text("ALTER TABLE solicitacao_correcao ADD COLUMN hora_original VARCHAR(8)"))
    colunas_feriado = [c["name"] for c in inspector.get_columns("feriado")]
    if "fonte" not in colunas_feriado:
        db.session.execute(text("ALTER TABLE feriado ADD COLUMN fonte VARCHAR(20) DEFAULT 'manual'"))

    db.session.execute(text("UPDATE usuario SET auth_version = COALESCE(auth_version, 0)"))
    db.session.commit()
    try:
        _sincronizar_feriados_lib()
    except Exception as exc:
        app.logger.warning("Falha ao sincronizar feriados na inicialização: %s", exc)


if app.config.get("AUTO_INIT_DB", False):
    with app.app_context():
        _apply_database_migrations()


@app.cli.command("init-db")
def init_db_command():
    """Cria/migra tabelas explicitamente (não é executado ao importar)."""
    _apply_database_migrations()
    click.echo("Banco de dados inicializado.")


@app.cli.command("bootstrap-admin")
@click.option("--email", prompt=True)
@click.option("--nome", prompt=True)
@click.option("--senha", prompt=True, hide_input=True, confirmation_prompt=True)
def bootstrap_admin(email, nome, senha):
    """Cria o primeiro administrador explicitamente por linha de comando."""
    email = email.strip().lower()
    nome = nome.strip()
    if not email or not nome or "@" not in email:
        raise click.ClickException("Informe nome e e-mail válidos.")
    if Usuario.query.filter_by(email=email).first():
        raise click.ClickException("Já existe uma conta com este e-mail.")
    problem = _password_problem(senha)
    if problem:
        raise click.ClickException(problem)
    user = Usuario(
        nome=nome,
        email=email,
        senha_hash=generate_password_hash(senha, method="scrypt"),
        is_admin=True,
        email_confirmado=True,
        precisa_redefinir_senha=False,
    )
    db.session.add(user)
    db.session.commit()
    click.echo(f"Administrador criado: {email}")


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
      - Janela de 30 dias para o cálculo de faltas (enquanto o mês ainda
        não passou do 5º dia útil).
      - Regra do 5º dia útil: após ele, o mês anterior é considerado
        fechado e deixa de gerar notificações de faltas/pontos incompletos.
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

    # ── 0. Regra do 5º dia útil: após ele, ignora meses anteriores ──
    # Antes do 5º dia útil o funcionário ainda pode regularizar pendências
    # do mês passado; depois disso, o mês anterior é considerado fechado.
    quinto_dia_util = _calcular_5o_dia_util_mes(hoje.year, hoje.month)
    if hoje >= quinto_dia_util:
        corte_notificacoes = date(hoje.year, hoje.month, 1)
    else:
        corte_notificacoes = hoje - timedelta(days=NOTIF_JANELA_DIAS)

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

        # ── 3. Faltas totais (janela de 30 dias ou mês atual, após 5º dia útil) ──
        # Calcula o limite: corte das notificações ou primeiro registro/cadastro,
        # o que vier antes. Após o 5º dia útil do mês, o corte é o dia 1º do mês
        # atual, então faltas de meses anteriores deixam de gerar notificação.
        usuario_obj = db.session.get(Usuario, user_id)
        data_inicio = (
            usuario_obj.data_cadastro.date()
            if usuario_obj and usuario_obj.data_cadastro
            else corte_notificacoes
        )
        limite_busca = max(
            corte_notificacoes,
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

        # ── 4. Pontos incompletos (janela de 30 dias ou mês atual, após 5º dia útil) ──
        janela_inicio = corte_notificacoes
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
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        user = Usuario.query.filter(db.func.lower(Usuario.email) == email).first()
        password_hash = user.senha_hash if user is not None else DUMMY_PASSWORD_HASH
        valid = check_password_hash(password_hash, senha)
        if valid and user is not None and user.email_confirmado:
            # Rotaciona o identificador da sessão antes de autenticar para
            # impedir fixação de sessão.
            session.clear()
            login_user(user)
            session.permanent = True
            session["_auth_version"] = int(user.auth_version or 0)
            if user.precisa_redefinir_senha:
                flash("Você precisa redefinir sua senha no primeiro acesso.", "info")
                return redirect(url_for("redefinir_senha_forca"))
            return redirect(url_for("index"))
        # A mesma resposta para e-mail inexistente, senha inválida ou e-mail
        # ainda não confirmado evita enumeração de contas.
        flash("E-mail ou senha incorretos.", "danger")
        return render_template("login.html", email=email)

    return render_template("login.html")

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        problem = _password_problem(senha)
        if problem:
            flash(problem, "danger")
            return render_template("register.html", nome=nome, email=email)

        # Validação de domínio
        if not verificar_dominio_email(email):
            flash("O domínio do e-mail é inválido ou não possui registros MX.", "danger")
            return render_template("register.html", nome=nome, email=email)

        if Usuario.query.filter(db.func.lower(Usuario.email) == email).first():
            # A mesma resposta para e-mail novo e existente evita enumeração.
            flash("Se os dados forem válidos, você poderá continuar o cadastro.", "info")
            return redirect(url_for("login"))

        # Verificar se a confirmação de e-mail está obrigatória (configurável no admin)
        verificacao_obrigatoria = _get_config("email_confirmacao_obrigatoria", "false").lower() == "true"

        if verificacao_obrigatoria:
            token, _row = issue_security_token(
                None,
                SecurityToken.PURPOSE_CONFIRM,
                app.config["CONFIRM_TOKEN_TTL_SECONDS"],
                email=email,
                nome=nome,
                senha_hash=generate_password_hash(senha, method="scrypt"),
            )
            confirm_url = _email_link("confirm_email", token=token)
            safe_name = html.escape(nome)
            sent = _send_email(
                email,
                "Confirme seu e-mail",
                f"<p>Olá {safe_name}, confirme seu e-mail.</p>{_email_link_html(confirm_url, 'Confirmar e-mail')}",
            )
            if sent:
                flash("Se os dados forem válidos, enviaremos as instruções por e-mail.", "info")
            else:
                flash("Não foi possível enviar o e-mail agora. Tente novamente.", "danger")
                return render_template("register.html", nome=nome, email=email)
        else:
            # Um usuário público nunca recebe privilégios de administrador por
            # ser o primeiro registro; bootstrap é feito apenas pela CLI.
            novo_usuario = Usuario(
                nome=nome,
                email=email,
                senha_hash=generate_password_hash(senha, method="scrypt"),
                is_admin=False,
                email_confirmado=True,
            )
            db.session.add(novo_usuario)
            db.session.commit()
            flash("Se os dados forem válidos, você poderá continuar o cadastro.", "info")

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Você saiu da conta.", "info")
    return redirect(url_for("login"))

@app.route("/redefinir_senha_forca", methods=["GET", "POST"])
@login_required
def redefinir_senha_forca():
    if request.method == "POST":
        senha = request.form.get("senha", "")

        problem = _password_problem(senha)
        if problem:
            flash(problem, "danger")
            return render_template("redefinir_senha_forca.html")

        current_user.senha_hash = generate_password_hash(senha, method="scrypt")
        current_user.precisa_redefinir_senha = False
        current_user.auth_version = int(current_user.auth_version or 0) + 1
        db.session.commit()
        registrar_log(current_user.id, "Redefiniu a própria senha (primeiro acesso)")
        flash("Senha alterada com sucesso! Faça login novamente.", "success")
        logout_user()
        session.clear()
        return redirect(url_for("login"))
    
    return render_template("redefinir_senha_forca.html")

@app.route("/alterar_senha", methods=["POST"])
@login_required
def alterar_senha():
    senha_atual = request.form.get("senha_atual", "")
    nova_senha = request.form.get("nova_senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")

    fallback = _internal_referrer_path(url_for("index"))
    if not check_password_hash(current_user.senha_hash, senha_atual):
        flash("A senha atual está incorreta.", "danger")
        return redirect(fallback)

    if nova_senha != confirmar_senha:
        flash("A confirmação da nova senha não confere.", "danger")
        return redirect(fallback)

    problem = _password_problem(nova_senha)
    if problem:
        flash(problem, "danger")
        return redirect(fallback)

    current_user.senha_hash = generate_password_hash(nova_senha, method="scrypt")
    current_user.auth_version = int(current_user.auth_version or 0) + 1
    db.session.commit()
    registrar_log(current_user.id, "Alterou a própria senha")
    flash("Senha alterada com sucesso! Faça login novamente.", "success")
    logout_user()
    session.clear()
    return redirect(url_for("login"))


_ADMIN_VIEW_ENDPOINTS = {
    "painel": "admin_panel",
    "usuarios": "admin_usuarios",
    "historico": "admin_historico",
    "solicitacoes": "admin_solicitacoes",
    "logs": "admin_logs",
}


def _redirect_admin(view_name):
    """Volta à aba que originou a ação, preservando seus filtros."""
    endpoint = _ADMIN_VIEW_ENDPOINTS.get(view_name, "admin_panel")
    query_pairs = list(request.args.items(multi=True))

    if not query_pairs:
        referrer = urlsplit(request.referrer or "")
        # O Referer só é consultado para preservar filtros; nunca é usado
        # como destino de redirect.
        if referrer.scheme in {"http", "https"}:
            allowed_netlocs = {urlsplit(app.config["PUBLIC_BASE_URL"]).netloc}
            allowed_netlocs.update(app.config["TRUSTED_HOSTS"])
            is_internal = referrer.netloc in allowed_netlocs
        else:
            is_internal = not referrer.netloc
        if is_internal and (referrer.path == "/admin" or referrer.path.startswith("/admin/")):
            query_pairs = parse_qsl(referrer.query, keep_blank_values=True)

    target = url_for(endpoint)
    if query_pairs:
        target = f"{target}?{urlencode(query_pairs)}"
    return redirect(target)


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
        return _redirect_admin("painel")

    usuario_alvo = db.session.get(Usuario, usuario_id)
    if not usuario_alvo:
        flash("Usuário não encontrado.", "danger")
        return _redirect_admin("painel")

    # Formatar data de YYYY-MM-DD para DD/MM/YYYY
    try:
        data_obj = datetime.strptime(data_raw, "%Y-%m-%d")
        data_formatada = data_obj.strftime("%d/%m/%Y")
    except ValueError:
        data_formatada = data_raw

    # Garantir formato HH:MM:SS para hora
    hora_formatada = hora_raw if len(hora_raw) == 8 else f"{hora_raw}:00"

    # --- Lógica automática: decide se cria novo ou substitui ---
    # Se já existe registro do mesmo tipo no dia, calcula a diferença de horário.
    # Diferença <= 2h (120 min) → ajuste/correção → substitui
    # Diferença >  2h (120 min) → ponto esquecido → cria novo
    ponto_existente = RegistroPonto.query.filter_by(
        usuario_id=usuario_alvo.id,
        data=data_formatada,
        tipo=tipo
    ).first()

    if ponto_existente:
        try:
            h1, m1, _ = map(int, hora_formatada.split(":"))
            h2, m2, _ = map(int, ponto_existente.hora.split(":"))
            diff_minutos = abs((h1 * 60 + m1) - (h2 * 60 + m2))
        except (ValueError, AttributeError):
            diff_minutos = 9999  # se falhar o parse, assume distante → cria novo

        if diff_minutos <= 120:
            # Horário parecido → substitui (é um ajuste)
            ponto_existente.hora = hora_formatada
            ponto_existente.foi_ajustado = True
            msg_acao = f"Atualizou o ponto ({tipo}) de {usuario_alvo.nome} para o dia {data_formatada} às {hora_formatada}."
        else:
            # Horário distante → cria novo (ponto esquecido / retorno de intervalo)
            novo_ponto = RegistroPonto(
                usuario_id=usuario_alvo.id,
                data=data_formatada,
                tipo=tipo,
                hora=hora_formatada,
                foi_ajustado=True
            )
            db.session.add(novo_ponto)
            msg_acao = f"Adicionou novo registro ({tipo}) de {usuario_alvo.nome} para o dia {data_formatada} às {hora_formatada}."
    else:
        # Nenhum registro existente → cria novo
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
    return _redirect_admin("painel")


@app.route("/admin/excluir-ponto/<int:ponto_id>", methods=["POST"])
@login_required
@admin_required
def admin_excluir_ponto(ponto_id):
    """Exclui um registro de ponto (apenas admin/RH). Usado para remover duplicatas."""
    ponto = RegistroPonto.query.get_or_404(ponto_id)
    usuario_alvo = db.session.get(Usuario, ponto.usuario_id)

    # Salvar dados para o log de auditoria ANTES de excluir
    nome_usuario = usuario_alvo.nome if usuario_alvo else "Usuário"
    desc_log = (
        f"Excluiu ponto ({ponto.tipo}) de {nome_usuario} "
        f"para o dia {ponto.data} às {ponto.hora}"
    )

    try:
        db.session.delete(ponto)
        db.session.commit()
        _invalidar_notif_cache(ponto.usuario_id)
    except Exception:
        db.session.rollback()
        flash("Erro ao excluir registro. Tente novamente.", "danger")
        return _redirect_admin("historico")

    registrar_log(current_user.id, desc_log, entidade_id=ponto.usuario_id)
    flash(f"Ponto ({ponto.tipo}) de {nome_usuario} excluído com sucesso!", "success")
    return _redirect_admin("historico")

@app.route("/admin/cadastrar_usuario", methods=["POST"])
@admin_required
def admin_cadastrar_usuario():
    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    
    if not nome or not email:
        flash("Nome e e-mail são obrigatórios.", "danger")
        return _redirect_admin("usuarios")

    if Usuario.query.filter_by(email=email).first():
        flash(f"Usuário {email} já cadastrado.", "danger")
        return _redirect_admin("usuarios")
    
    # Criar usuário temporário para gerar o token
    senha_temporaria = secrets.token_urlsafe(32)
    tipo_contrato = request.form.get("tipo_contrato", "CLT").strip().upper()
    if tipo_contrato not in ("CLT", "PJ"):
        tipo_contrato = "CLT"
    novo_usuario = Usuario(
        nome=nome,
        email=email,
        senha_hash=generate_password_hash(senha_temporaria, method="scrypt"),
        precisa_redefinir_senha=True,
        email_confirmado=True,
        tipo_contrato=tipo_contrato
    )
    db.session.add(novo_usuario)
    db.session.commit()
    registrar_log(current_user.id, f"Cadastrou usuário {nome} ({email})")
    
    token, _row = issue_security_token(
        novo_usuario.id,
        SecurityToken.PURPOSE_INVITE,
        app.config["INVITE_TOKEN_TTL_SECONDS"],
    )
    link_definir_senha = _email_link("definir_senha_usuario", token=token)
    safe_name = html.escape(nome)
    sent = _send_email(
        email,
        "Bem-vindo ao 4Lab Orbit - Defina sua senha",
        f"<p>Olá {safe_name}, seu cadastro foi realizado pelo administrador.</p>{_email_link_html(link_definir_senha, 'Definir senha')}",
    )
    if sent:
        flash(f"Usuário {nome} cadastrado com sucesso! E-mail de convite enviado.", "success")
    else:
        flash("Usuário cadastrado, mas não foi possível enviar o convite. Gere um novo convite.", "danger")

    return _redirect_admin("usuarios")

@app.route("/definir_senha/<token>", methods=["GET", "POST"])
def definir_senha_usuario(token):
    row = _get_valid_security_token(token, SecurityToken.PURPOSE_INVITE)
    if not row or not row.usuario:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        senha = request.form.get("senha", "")
        problem = _password_problem(senha)
        if problem:
            flash(problem, "danger")
            return render_template("redefinir_senha_forca.html", invite_token=token)
        # Consome somente depois de validar a nova senha; replay posterior falha.
        consumed = consume_security_token(token, SecurityToken.PURPOSE_INVITE)
        if not consumed or not consumed.usuario:
            flash("Token inválido ou expirado.", "danger")
            return redirect(url_for("login"))
        usuario = consumed.usuario
        usuario.senha_hash = generate_password_hash(senha, method="scrypt")
        usuario.precisa_redefinir_senha = False
        usuario.auth_version = int(usuario.auth_version or 0) + 1
        db.session.commit()
        session.clear()
        login_user(usuario)
        session.permanent = True
        session["_auth_version"] = int(usuario.auth_version or 0)
        flash("Senha definida com sucesso!", "success")
        return redirect(url_for("index"))

    return render_template("redefinir_senha_forca.html", invite_token=token)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = Usuario.query.filter(db.func.lower(Usuario.email) == email).first()
        if user:
            token, _row = issue_security_token(
                user.id,
                SecurityToken.PURPOSE_RESET,
                app.config["RESET_TOKEN_TTL_SECONDS"],
            )
            reset_link = _email_link("reset_password", token=token)
            safe_name = html.escape(user.nome)
            _send_email(
                email,
                "Redefinição de Senha",
                f"<p>Olá {safe_name}, use o link abaixo para redefinir sua senha.</p>{_email_link_html(reset_link, 'Redefinir senha')}",
            )
        # A resposta é a mesma para qualquer endereço, inclusive inexistente.
        flash("Se o e-mail estiver cadastrado, você receberá instruções para redefinir a senha.", "info")

    return render_template("forgot_password.html")


@app.route("/confirm_email/<token>", methods=["GET", "POST"])
def confirm_email(token):
    row = _get_valid_security_token(token, SecurityToken.PURPOSE_CONFIRM)
    if not row or not row.email or not row.nome or not row.senha_hash:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("login"))

    if Usuario.query.filter_by(email=row.email).first():
        # Consome também um token de confirmação já usado para evitar replay.
        consume_security_token(token, SecurityToken.PURPOSE_CONFIRM)
        flash("Este e-mail já foi confirmado/cadastrado.", "warning")
        return redirect(url_for("login"))

    if request.method == "GET":
        # A mensagem de um cliente de e-mail não consome o token; a confirmação
        # exige uma ação POST protegida por CSRF.
        return render_template("confirm_email.html", token=token)

    # Consome atomicamente antes de criar a conta; nenhum usuário público é
    # promovido a administrador.
    consumed = consume_security_token(token, SecurityToken.PURPOSE_CONFIRM)
    if not consumed:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("login"))
    novo_usuario = Usuario(
        nome=consumed.nome,
        email=consumed.email,
        senha_hash=consumed.senha_hash,
        is_admin=False,
        email_confirmado=True,
    )
    db.session.add(novo_usuario)
    db.session.commit()
    flash("E-mail confirmado com sucesso! Você já pode fazer login.", "success")
    return redirect(url_for("login"))


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    row = _get_valid_security_token(token, SecurityToken.PURPOSE_RESET)
    if not row or not row.usuario:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        senha = request.form.get("senha", "")
        problem = _password_problem(senha)
        if problem:
            flash(problem, "danger")
            return render_template("reset_password.html")
        consumed = consume_security_token(token, SecurityToken.PURPOSE_RESET)
        if not consumed or not consumed.usuario:
            flash("Token inválido ou expirado.", "danger")
            return redirect(url_for("forgot_password"))
        usuario = consumed.usuario
        usuario.senha_hash = generate_password_hash(senha, method="scrypt")
        usuario.precisa_redefinir_senha = False
        usuario.auth_version = int(usuario.auth_version or 0) + 1
        db.session.commit()
        session.clear()
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
    ).order_by(RegistroPonto.hora.asc()).all()

    # Último ponto: primeiro busca o ponto mais recente de HOJE (por hora),
    # para que ajustes/correções com ID alto não distorçam o resultado.
    ultimo_ponto_obj = (
        RegistroPonto.query.filter_by(usuario_id=current_user.id, data=data_hoje)
        .order_by(RegistroPonto.hora.desc())
        .first()
    )
    # Fallback: se hoje ainda não houve batida, mostra o último registro global
    # (com a data) para o card não ficar vazio de manhã.
    if not ultimo_ponto_obj:
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
    try:
        db.session.commit()
        _invalidar_notif_cache(current_user.id)
    except Exception:
        db.session.rollback()
        flash("Erro ao registrar ponto. Tente novamente.", "danger")
        return redirect(url_for("index"))

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
    ).order_by(RegistroPonto.hora.asc()).all()

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
    try:
        db.session.commit()
        _invalidar_notif_cache(current_user.id)
    except Exception:
        db.session.rollback()
        flash("Erro ao registrar ponto automaticamente. Tente novamente.", "danger")
        return redirect(url_for("index"))

    flash(f"Ponto ({proximo}) registrado às {hora_atual} com sucesso!", "success")
    return redirect(url_for("index"))

@app.route("/meu_historico")
@login_required
def meu_historico():
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    data_inicio_str = request.args.get("data_inicio", "").strip()
    data_fim_str = request.args.get("data_fim", "").strip()
    tipo_ponto = request.args.get("tipo_ponto", "").strip()

    data_inicio_obj = None
    data_fim_obj = None
    if data_inicio_str:
        try:
            data_inicio_obj = datetime.strptime(data_inicio_str, "%Y-%m-%d").date()
        except ValueError:
            pass
    if data_fim_str:
        try:
            data_fim_obj = datetime.strptime(data_fim_str, "%Y-%m-%d").date()
        except ValueError:
            pass

    if not data_fim_obj:
        data_fim_obj = hoje
    if not data_inicio_obj:
        # Sem período explícito, assume o mês corrente até hoje — mesma
        # regra usada na folha de ponto exportada.
        data_inicio_obj = data_fim_obj.replace(day=1)

    if data_inicio_obj > data_fim_obj:
        data_inicio_obj = data_fim_obj

    query = RegistroPonto.query.filter_by(usuario_id=current_user.id)
    if tipo_ponto in PONTOS_PERMITIDOS:
        query = query.filter_by(tipo=tipo_ponto)

    registros = query.order_by(RegistroPonto.id.desc()).all()

    dias_registrados = {}
    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            if data_inicio_obj <= d_obj <= data_fim_obj:
                if d_obj not in dias_registrados:
                    dias_registrados[d_obj] = []
                dias_registrados[d_obj].append(r)
        except ValueError:
            pass

    historico_analisado = []
    datas_intervalo = []
    temp_date = data_inicio_obj
    while temp_date <= data_fim_obj:
        datas_intervalo.append(temp_date)
        temp_date += timedelta(days=1)

    datas_intervalo.sort(reverse=True)

    for d_obj in datas_intervalo:
        data_str = d_obj.strftime("%d/%m/%Y")
        registros_do_dia = dias_registrados.get(d_obj, [])
        registros_do_dia = sorted(
            registros_do_dia,
            key=lambda r: _parse_hora(getattr(r, "hora", None)) or datetime.min.time()
        )

        # Se NÃO for dia útil e NÃO houver registros, pula o dia
        if not eh_dia_util(d_obj) and not registros_do_dia:
            continue

        saldo = calcular_saldo_dia(registros_do_dia, d_obj)
        incompleto = dia_ponto_incompleto(registros_do_dia) or not registros_do_dia

        historico_analisado.append({
            "data": data_str,
            "registros": registros_do_dia,
            "incompleto": incompleto,
            "saldo": saldo,
        })

    return render_template(
        "meu_historico.html",
        historico=historico_analisado,
        data_inicio=data_inicio_obj.isoformat(),
        data_fim=data_fim_obj.isoformat(),
        tipo_ponto=tipo_ponto,
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
        hora_original = request.form.get("hora_original", "").strip() or None

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

        # Se hora_original veio no formato HH:MM (5 chars), completa para HH:MM:SS
        if hora_original and len(hora_original) == 5:
            hora_original += ":00"

        solicitacao = SolicitacaoCorrecao(
            data_ponto=data_formatada,
            tipo_ponto=tipo_ponto,
            hora_original=hora_original,
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

@app.route("/api/pontos-do-dia/<data_iso>")
@login_required
def api_pontos_do_dia(data_iso):
    """Retorna em JSON os registros de ponto do usuário logado para a data informada (YYYY-MM-DD)."""
    try:
        data_obj = datetime.strptime(data_iso, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"erro": "Data inválida"}), 400

    data_br = data_obj.strftime("%d/%m/%Y")

    registros = RegistroPonto.query.filter_by(
        usuario_id=current_user.id,
        data=data_br
    ).order_by(RegistroPonto.hora.asc()).all()

    resultado = [
        {
            "id": r.id,
            "tipo": r.tipo,
            "hora": r.hora,
            "hora_display": r.hora[:5] if len(r.hora) >= 5 else r.hora,
        }
        for r in registros
    ]
    return jsonify(resultado)

def _gerar_relatorio_ponto_dados(usuario, data_inicio_str=None, data_fim_str=None):
    hoje_real = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    is_pj = getattr(usuario, "tipo_contrato", "CLT") == "PJ"

    data_inicio_obj = None
    data_fim_obj = None
    if data_inicio_str:
        try:
            data_inicio_obj = datetime.strptime(data_inicio_str, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            pass
    if data_fim_str:
        try:
            data_fim_obj = datetime.strptime(data_fim_str, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            pass

    if not data_fim_obj:
        data_fim_obj = hoje_real

    if not data_inicio_obj:
        if data_fim_str:
            data_inicio_obj = data_fim_obj.replace(day=1)
        else:
            data_inicio_obj = hoje_real.replace(day=1)

    if data_inicio_obj > data_fim_obj:
        data_inicio_obj = data_fim_obj

    registros = RegistroPonto.query.filter_by(usuario_id=usuario.id).order_by(RegistroPonto.id.asc()).all()

    dias_registrados = defaultdict(list)
    for r in registros:
        try:
            d_obj = datetime.strptime(r.data, "%d/%m/%Y").date()
            if data_inicio_obj <= d_obj <= data_fim_obj:
                if r.tipo in PONTOS_PERMITIDOS:
                    dias_registrados[d_obj].append((r.tipo, r.hora))
        except (ValueError, TypeError):
            pass

    for d in dias_registrados:
        dias_registrados[d].sort(key=lambda x: x[1])

    max_pares = 1
    for d_obj in range(data_inicio_obj.toordinal(), data_fim_obj.toordinal() + 1):
        regs_dia = dias_registrados.get(date.fromordinal(d_obj), [])
        pares = (len(regs_dia) + 1) // 2
        if pares > max_pares:
            max_pares = pares

    cabecalho = ["Dia"]
    for n in range(1, max_pares + 1):
        cabecalho.append(f"Entrada {n}")
        cabecalho.append(f"Saída {n}")
    cabecalho.append("Total / Status")
    tabela_linhas = [cabecalho]

    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    total_segundos_faltantes = 0
    total_faltas_dias = 0
    FMT = "%H:%M:%S"
    segundos_carga_diaria = int(CARGA_HORARIA_DIARIA.total_seconds())

    curr = data_inicio_obj
    while curr <= data_fim_obj:
        dia_str = curr.strftime("%d/%m/%Y")
        regs = dias_registrados.get(curr, [])

        if regs:
            entradas = []
            saidas = []
            for tipo, hora in regs:
                if tipo == "Entrada":
                    entradas.append(hora)
                elif tipo == "Saída":
                    saidas.append(hora)

            tempo_trabalhado = timedelta()
            for i in range(min(len(entradas), len(saidas))):
                try:
                    t1, t2 = datetime.strptime(entradas[i], FMT), datetime.strptime(saidas[i], FMT)
                    if t2 > t1:
                        tempo_trabalhado += t2 - t1
                except (ValueError, TypeError):
                    pass

            tot = int(tempo_trabalhado.total_seconds())
            total_segundos_trabalhados += tot

            dia_encerrado = bool(regs) and regs[-1][0] == "Saída"
            if not is_pj:
                if tot > segundos_carga_diaria:
                    total_segundos_extras += (tot - segundos_carga_diaria)
                elif (curr < hoje_real or dia_encerrado) and eh_dia_util(curr) and tot < segundos_carga_diaria:
                    total_segundos_faltantes += (segundos_carga_diaria - tot)

            linha = [dia_str]
            for i, (tipo, hora) in enumerate(regs):
                esperado = "Entrada" if i % 2 == 0 else "Saída"
                cel = hora[:5]
                if tipo != esperado:
                    cel = f"E {cel}" if tipo == "Entrada" else f"S {cel}"
                linha.append(cel)
            while len(linha) < len(cabecalho) - 1:
                linha.append("")
            hrs, mins = divmod(tot // 60, 60)
            linha.append(f"{hrs:02d}:{mins:02d}h")
            tabela_linhas.append(linha)

        elif eh_dia_util(curr):
            if not is_pj:
                vazios = [""] * (len(cabecalho) - 2)
                if curr < hoje_real:
                    total_faltas_dias += 1
                    total_segundos_faltantes += segundos_carga_diaria
                    tabela_linhas.append([dia_str, *vazios, "FALTA"])
                elif curr == hoje_real:
                    tabela_linhas.append([dia_str, *vazios, "Em Aberto"])
                else:
                    tabela_linhas.append([dia_str, *vazios, "-"])

        curr += timedelta(days=1)

    balanco_segundos = total_segundos_extras - total_segundos_faltantes
    hrs_t, mins_t = divmod(total_segundos_trabalhados // 60, 60)
    hrs_e, mins_e = divmod(total_segundos_extras // 60, 60)
    hrs_f, mins_f = divmod(total_segundos_faltantes // 60, 60)
    hrs_b, mins_b = divmod(abs(balanco_segundos) // 60, 60)

    texto_balanco = f"+{hrs_b:02d}:{mins_b:02d}h (Crédito)" if balanco_segundos >= 0 else f"-{hrs_b:02d}:{mins_b:02d}h (A Repor)"
    cor_balanco = colors.HexColor("#2e7d32") if balanco_segundos >= 0 else colors.HexColor("#c62828")

    return {
        "usuario": usuario,
        "is_pj": is_pj,
        "data_inicio_obj": data_inicio_obj,
        "data_fim_obj": data_fim_obj,
        "tabela_linhas": tabela_linhas,
        "max_pares": max_pares,
        "total_segundos_trabalhados": total_segundos_trabalhados,
        "total_segundos_extras": total_segundos_extras,
        "total_segundos_faltantes": total_segundos_faltantes,
        "total_faltas_dias": total_faltas_dias,
        "hrs_t": hrs_t,
        "mins_t": mins_t,
        "hrs_e": hrs_e,
        "mins_e": mins_e,
        "hrs_f": hrs_f,
        "mins_f": mins_f,
        "hrs_b": hrs_b,
        "mins_b": mins_b,
        "balanco_segundos": balanco_segundos,
        "texto_balanco": texto_balanco,
        "cor_balanco": cor_balanco,
    }


def _gerar_arquivo_folha_ponto(dados, formato):
    usuario = dados["usuario"]
    is_pj = dados["is_pj"]
    data_inicio_obj = dados["data_inicio_obj"]
    data_fim_obj = dados["data_fim_obj"]
    tabela_linhas = dados["tabela_linhas"]
    max_pares = dados["max_pares"]

    if formato == "pdf":
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        elementos = []
        estilos = getSampleStyleSheet()

        titulo_estilo = ParagraphStyle("T", parent=estilos["Heading1"], fontSize=18, alignment=1, spaceAfter=15)
        elementos.append(Paragraph(f"<b>Folha de Ponto - {_pdf_text(usuario.nome)}</b>", titulo_estilo))
        periodo_str = f"{data_inicio_obj.strftime('%d/%m/%Y')} a {data_fim_obj.strftime('%d/%m/%Y')}"
        elementos.append(
            Paragraph(
                f"<b>E-mail:</b> {_pdf_text(usuario.email)} | <b>Contrato:</b> {'PJ' if is_pj else 'CLT'} | <b>Período:</b> {periodo_str} | <b>Emissão:</b> {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y às %H:%M')}",
                estilos["Normal"]
            )
        )
        elementos.append(Spacer(1, 15))

        largura_util = pdf.rightMargin + pdf.leftMargin + (letter[0] - pdf.rightMargin - pdf.leftMargin)
        col_batidas = max(1, max_pares * 2)
        larg_batida = max(38.0, (largura_util - 80 - 90) / col_batidas)
        colWidths = [80] + [larg_batida] * col_batidas + [90]
        tabela = Table(tabela_linhas, colWidths=colWidths)
        estilo_tabela = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ]
        for i, linha in enumerate(tabela_linhas[1:], start=1):
            if "FALTA" in linha:
                estilo_tabela.append(("TEXTCOLOR", (0, i), (-1, i), colors.HexColor("#d32f2f")))
                estilo_tabela.append(("FONTNAME", (0, i), (-1, i), "Helvetica-Bold"))
                estilo_tabela.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffebee")))

        tabela.setStyle(TableStyle(estilo_tabela))
        elementos.append(tabela)
        elementos.append(Spacer(1, 20))

        dados_resumo = [
            ["Horas Totais Trabalhadas:", f"{dados['hrs_t']:02d}:{dados['mins_t']:02d}h"],
        ]
        if not is_pj:
            dados_resumo.append(["(+) Total Horas Extras:", f"{dados['hrs_e']:02d}:{dados['mins_e']:02d}h"])
            dados_resumo.append(["(-) Total Horas Faltantes:", f"{dados['hrs_f']:02d}:{dados['mins_f']:02d}h ({dados['total_faltas_dias']} dia(s) ausente)"])
            dados_resumo.append(["BALANÇO FINAL (BANCO DE HORAS):", dados["texto_balanco"]])

        tabela_resumo = Table(dados_resumo, colWidths=[310, 200])
        resumo_estilos = [
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ]
        if not is_pj:
            resumo_estilos.append(("TEXTCOLOR", (1, 3), (1, 3), dados["cor_balanco"]))
            resumo_estilos.append(("LINEABOVE", (0, 3), (-1, 3), 1, colors.HexColor("#000000")))
        tabela_resumo.setStyle(TableStyle(resumo_estilos))
        elementos.append(tabela_resumo)

        pdf.build(elementos)
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name="Folha_Ponto.pdf",
            mimetype="application/pdf",
        )

    import pandas as pd
    safe_rows = _safe_export_rows(tabela_linhas[1:])
    df = pd.DataFrame(safe_rows, columns=tabela_linhas[0])

    if formato == "excel":
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Ponto')
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name="Folha_Ponto.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    if formato == "csv":
        output = io.StringIO()
        df.to_csv(output, index=False, encoding='utf-8-sig')
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')),
            as_attachment=True,
            download_name="Folha_Ponto.csv",
            mimetype="text/csv"
        )

    return None


@app.route("/exportar-ponto")
@login_required
def exportar_historico_ponto():
    formato = request.args.get('format', 'pdf')
    data_inicio = request.args.get('data_inicio', '').strip()
    data_fim = request.args.get('data_fim', '').strip()
    dados = _gerar_relatorio_ponto_dados(current_user, data_inicio, data_fim)
    resp = _gerar_arquivo_folha_ponto(dados, formato)
    if resp:
        return resp
    return redirect(url_for("meu_historico"))
# ==========================================
#   ROTAS DE UPLOAD, DEPARTAMENTOS & RBAC
# ==========================================
UPLOAD_FOLDER = app.config["UPLOAD_FOLDER"]

@app.route("/perfil/upload-foto", methods=["POST"])
@login_required
def upload_foto_perfil():
    fallback = _internal_referrer_path(url_for("index"))
    uploaded = request.files.get("foto")
    if uploaded is None or not uploaded.filename:
        flash("Nenhum arquivo enviado.", "warning")
        return redirect(fallback)

    if uploaded.content_length and uploaded.content_length > app.config["UPLOAD_MAX_BYTES"]:
        flash("A imagem excede o tamanho máximo de 2 MB.", "danger")
        return redirect(fallback)

    try:
        output_format = _validate_profile_image(uploaded.stream)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(fallback)

    extension = {"PNG": "png", "JPEG": "jpg", "GIF": "gif"}[output_format]
    filename = f"user_{current_user.id}_{secrets.token_hex(12)}.{extension}"
    upload_folder = app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.abspath(os.path.join(upload_folder, filename))
    if os.path.commonpath([os.path.abspath(upload_folder), filepath]) != os.path.abspath(upload_folder):
        flash("Não foi possível salvar a imagem.", "danger")
        return redirect(fallback)
    uploaded.stream.seek(0)
    uploaded.save(filepath)

    old_url = current_user.foto_url
    old_filename = old_url.rsplit("/", 1)[-1] if old_url else ""
    if re.fullmatch(r"user_\d+_[0-9a-f]{24}\.(?:png|jpg|gif)", old_filename):
        if old_url.startswith("/uploads/perfil/"):
            old_path = os.path.abspath(os.path.join(upload_folder, old_filename))
        else:
            old_path = os.path.abspath(os.path.join(app.root_path, "static", "uploads", "perfil", old_filename))
        if os.path.dirname(old_path) in {os.path.abspath(upload_folder), os.path.abspath(os.path.join(app.root_path, "static", "uploads", "perfil"))}:
            try:
                os.remove(old_path)
            except OSError:
                pass

    current_user.foto_url = f"/uploads/perfil/{filename}"
    db.session.commit()
    registrar_log(current_user.id, "Atualizou foto de perfil")
    flash("Foto de perfil atualizada com sucesso!", "success")
    return redirect(fallback)

@app.route("/uploads/perfil/<path:filename>")
@login_required
def uploaded_profile_image(filename):
    if not re.fullmatch(r"user_\d+_[0-9a-f]{24}\.(?:png|jpg|gif)", filename):
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, max_age=0)


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
        return _redirect_admin("usuarios")

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
    return _redirect_admin("usuarios")

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

    # Atualizar Tipo de Contrato (CLT / PJ)
    tipo_contrato = request.form.get("tipo_contrato", "").strip().upper()
    if tipo_contrato in ("CLT", "PJ"):
        user.tipo_contrato = tipo_contrato
    
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
    user.auth_version = int(user.auth_version or 0) + 1
    db.session.commit()
    registrar_log(current_user.id, f"Atualizou departamento e permissões do usuário {user.nome}", user_id)
    flash(f"Dados e permissões do colaborador {user.nome} salvos com sucesso!", "success")
    return _redirect_admin("usuarios")

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

@app.route("/admin/toggle-verificacao-email", methods=["POST"])
@login_required
@admin_required
def toggle_verificacao_email():
    """Alterna a verificação de e-mail obrigatória no cadastro público."""
    ativa = _get_config("email_confirmacao_obrigatoria", "false").lower() == "true"
    _set_config("email_confirmacao_obrigatoria", "false" if ativa else "true")
    db.session.commit()
    registrar_log(current_user.id, f"{'Reativou' if not ativa else 'Desativou'} a verificação de e-mail no cadastro")
    status = "ativada" if not ativa else "desativada"
    flash(f"Verificação de e-mail no cadastro {status}.", "success")
    return _redirect_admin("usuarios")

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
        email_verificacao_ativa = _get_config("email_confirmacao_obrigatoria", "false").lower() == "true"
        return render_template("admin_fragment_usuarios.html", usuarios=usuarios, departamentos=departamentos, total_solicitacoes_pendentes=total_solicitacoes_pendentes, email_verificacao_ativa=email_verificacao_ativa)

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

        # Ordena cronologicamente (data DESC, hora DESC) para exibição correta:
        # correções tardias têm ID alto mas hora antiga.
        def _chave_crono(r):
            try:
                d = datetime.strptime(r.data, "%d/%m/%Y") if r.data else datetime.min
            except (ValueError, TypeError):
                d = datetime.min
            return (d, r.hora or "")
        registros = sorted(registros, key=_chave_crono, reverse=True)

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

    return _redirect_admin("painel")

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

    # Ordena cronologicamente (data DESC, hora DESC) para exibição correta:
    # correções tardias têm ID alto mas hora antiga.
    def _chave_crono(r):
        try:
            d = datetime.strptime(r.data, "%d/%m/%Y") if r.data else datetime.min
        except (ValueError, TypeError):
            d = datetime.min
        return (d, r.hora or "")
    registros = sorted(registros, key=_chave_crono, reverse=True)

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

        if solicitacao.hora_original:
            # Correção de registro EXISTENTE: busca o registro específico (mesma data, tipo E hora)
            ponto_existente = RegistroPonto.query.filter_by(
                usuario_id=solicitacao.usuario_id,
                data=solicitacao.data_ponto,
                tipo=solicitacao.tipo_ponto,
                hora=solicitacao.hora_original
            ).first()

            if ponto_existente:
                ponto_existente.hora = solicitacao.hora_correta
                ponto_existente.foi_ajustado = True
                descricao_acao = f"Aprovou correção de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}"
            else:
                # Registro original não encontrado (pode ter sido excluído); cria novo
                novo_ponto = RegistroPonto(
                    data=solicitacao.data_ponto,
                    tipo=solicitacao.tipo_ponto,
                    hora=solicitacao.hora_correta,
                    usuario_id=solicitacao.usuario_id,
                    foi_ajustado=True
                )
                db.session.add(novo_ponto)
                descricao_acao = f"Aprovou correção (registro original não encontrado, criou novo) de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}"
        else:
            # Ponto ESQUECIDO / nunca registrado: SEMPRE cria um registro NOVO,
            # preservando registros existentes do mesmo tipo no dia.
            novo_ponto = RegistroPonto(
                data=solicitacao.data_ponto,
                tipo=solicitacao.tipo_ponto,
                hora=solicitacao.hora_correta,
                usuario_id=solicitacao.usuario_id,
                foi_ajustado=True
            )
            db.session.add(novo_ponto)
            descricao_acao = f"Aprovou novo registro (ponto esquecido) de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}"

        registrar_log(current_user.id, descricao_acao, id)
        flash("Solicitação APROVADA e registro atualizado!", "success")

    elif acao == "recusar":
        solicitacao.status = "Recusada"
        registrar_log(current_user.id, f"Recusou ajuste de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}", id)
        flash("Solicitação RECUSADA.", "warning")

    db.session.commit()
    _invalidar_notif_cache(solicitacao.usuario_id)
    return _redirect_admin("solicitacoes")

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
@admin_required
def toggle_admin(user_id):
    user = Usuario.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Você não pode alterar suas próprias permissões de administrador.", "warning")
    else:
        user.is_admin = not user.is_admin
        user.auth_version = int(user.auth_version or 0) + 1
        db.session.commit()
        registrar_log(current_user.id, f"Alterou permissão de admin para {user.nome} -> {user.is_admin}", user_id)
        flash(f"Permissões do usuário {user.nome} atualizadas com sucesso!", "success")
    return _redirect_admin("usuarios")

def registrar_log(usuario_id, acao, entidade_id=None):
    log = LogAuditoria(usuario_id=usuario_id, acao=acao, entidade_id=entidade_id)
    db.session.add(log)
    db.session.commit()

@app.route("/admin/excluir-usuario/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def excluir_usuario(user_id):
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
        SecurityToken.query.filter_by(usuario_id=user.id).delete()
        
        db.session.delete(user)
        db.session.commit()
        _invalidar_notif_cache(user_id)
        
        registrar_log(current_user.id, f"Excluiu usuário {user_nome}", user_id)

        flash(f"Usuário {user_nome} excluído com sucesso!", "success")

    return _redirect_admin("usuarios")

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
    # Re-ordena cronologicamente: correções tardias podem ter ID alto mas hora antiga
    registros = sorted(
        registros,
        key=lambda r: (datetime.strptime(r.data, "%d/%m/%Y") if r.data else datetime.min, r.hora or "")
    )
    
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
@admin_required
def admin_exportar_ponto(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    formato = request.args.get('format', 'pdf')
    data_inicio = request.args.get('data_inicio', '').strip()
    data_fim = request.args.get('data_fim', '').strip()
    dados = _gerar_relatorio_ponto_dados(usuario, data_inicio, data_fim)
    resp = _gerar_arquivo_folha_ponto(dados, formato)
    if resp:
        return resp
    return _redirect_admin("painel")

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
    return _redirect_admin("painel")

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
    return _redirect_admin("painel")

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
    return _redirect_admin("painel")

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
            reg = db.session.get(Configuracao, chave)
            if reg is not None:
                db.session.delete(reg)
        db.session.commit()
        _invalidar_cache_regiao()
        _sincronizar_feriados_lib()
        flash("Feriados regionais definidos como nacionais (BR).", "success")
        return _redirect_admin("painel")

    if uf not in UFS_BRASIL:
        flash("Sigla de UF inválida.", "danger")
        return _redirect_admin("painel")

    try:
        _set_config("uf_feriado", uf)
        _set_config("regiao_fonte", "manual")
        # Remove a cidade (não faz sentido para definição manual por UF)
        reg_cidade = db.session.get(Configuracao, "cidade_feriado")
        if reg_cidade is not None:
            db.session.delete(reg_cidade)
        db.session.commit()
        _invalidar_cache_regiao()
        _sincronizar_feriados_lib()
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao definir a região: {e}", "danger")
        return _redirect_admin("painel")

    flash(f"Feriados regionais definidos para {uf} ({UFS_BRASIL[uf]}).", "success")
    return _redirect_admin("painel")

@app.route("/admin/enviar-lembrete-geral", methods=["POST"])
@login_required
@admin_required
def enviar_lembrete_geral():
    mensagem = request.form.get("mensagem", "").strip()

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

    return _redirect_admin("painel")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
