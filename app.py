import io
import math
import os
import re
import time
import hashlib
import html
import secrets
import struct
import threading
import click
import holidays
import calendar

from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, date
from functools import wraps
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit
from zoneinfo import ZoneInfo
from xml.sax.saxutils import escape as xml_escape

import requests

from flask import (
    Flask,
    g,
    flash,
    get_flashed_messages,
    has_request_context,
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
from markupsafe import Markup
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from PIL import Image, ImageOps, UnidentifiedImageError
from dotenv import load_dotenv
import resend

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
# No Heroku (variável DYNO sempre presente) o padrão é produção: esquecer o
# APP_ENV não pode desligar em silêncio as exigências de segurança abaixo.
ON_HEROKU = bool(os.environ.get("DYNO"))
_APP_ENV_PADRAO = "production" if ON_HEROKU else "development"
APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", _APP_ENV_PADRAO)).strip().lower()
IS_PRODUCTION = APP_ENV not in {"development", "dev", "test", "testing", "local"}
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    if TESTING:
        SECRET_KEY = "testing-key"
    else:
        raise RuntimeError(
            "\n" + "="*60 + "\n"
            "ERRO: SECRET_KEY NÃO ENCONTRADA\n" + "="*60 + "\n"
            "Para resolver este erro de deploy:\n\n"
            "1. Se estiver no HEROKU: rode 'heroku config:set SECRET_KEY=$(python -c \"import secrets; print(secrets.token_hex(32))\")'\n"
            "2. Se estiver no RENDER/RAILWAY: Adicione 'SECRET_KEY' nas Environment Variables.\n"
            "3. Se estiver LOCAL: Adicione 'SECRET_KEY=chave_aleatoria' no seu arquivo .env\n\n"
            "DICA: Você pode gerar uma chave agora com: flask generate-secret\n" + "="*60
        )

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
# Chave de exemplo que já esteve publicada no SECURITY.md: quem a copiou
# precisa gerar outra (com ela, qualquer um forja cookies de sessão).
if IS_PRODUCTION and SECRET_KEY == "2d757d696d5190632b338f929beaf23dd7043c4eb35d9ad3cdb1dff19e6937ea":
    raise RuntimeError("SECRET_KEY é a chave de exemplo da documentação. Gere uma nova.")
public_base_url = _normalise_public_base_url(os.environ.get("PUBLIC_BASE_URL", ""))
if not public_base_url:
    if IS_PRODUCTION:
        raise RuntimeError("PUBLIC_BASE_URL ausente: configure a URL pública da aplicação.")
    public_base_url = "http://localhost:1234"
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
# Nome próprio: outro app Flask no mesmo host (cookies não separam por porta)
# usaria o padrão "session" e sobrescreveria a sessão, quebrando o CSRF.
# Com HTTPS, o prefixo __Host- impede que subdomínios definam o cookie.
app.config["SESSION_COOKIE_NAME"] = "__Host-ponto_session" if cookie_secure else "ponto_session"
app.config["REMEMBER_COOKIE_NAME"] = "__Host-ponto_remember" if cookie_secure else "ponto_remember"
# O roteador do Heroku é exatamente um proxy e acrescenta o IP real do
# cliente ao final do X-Forwarded-For, então lá o padrão é confiar nele.
app.config["TRUST_PROXY_HEADERS"] = _env_bool("TRUST_PROXY_HEADERS", ON_HEROKU)
if app.config["TRUST_PROXY_HEADERS"]:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
# Redirecionar para HTTPS só é seguro quando o esquema original é conhecido
# (sem o ProxyFix, toda requisição atrás do proxy parece HTTP: laço infinito).
app.config["FORCE_HTTPS"] = IS_PRODUCTION and app.config["TRUST_PROXY_HEADERS"]

# "Esqueci minha senha" depende de e-mail (Resend com domínio verificado).
# Enquanto estiver desligado, a troca de senha é feita pelo RH.
app.config["ESQUECI_SENHA_ATIVO"] = _env_bool("ESQUECI_SENHA_ATIVO", False)
_MSG_SENHA_PELO_RH = "Esqueceu a senha? Peça ao RH para definir uma nova."

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
app.config["RATE_LIMIT_ENABLED"] = _env_bool("RATE_LIMIT_ENABLED", True)
app.config["RATE_LIMITS"] = {
    # Por IP. Por conta há um limite próprio (TentativaLogin), comum a todos
    # os workers, que segura ataques distribuídos em muitos IPs.
    "login": (30, 300),
    "forgot_password": (5, 900),
    "upload": (10, 900),
    "reset_password": (10, 900),
    "definir_senha_usuario": (10, 900),
    "api_localizacao": (30, 900),
    "push_teste": (5, 600),
}
app.config["CSRF_FIELD_NAME"] = "_csrf_token"
app.config["CSRF_HEADER_NAME"] = "X-CSRF-Token"
app.config["MAIL_FROM"] = os.environ.get("MAIL_FROM", "onboarding@resend.dev")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


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


# Dia útil = dia de trabalho da jornada vigente (padrão: segunda a sexta) e
# que não seja feriado.
def eh_dia_util(data_obj, departamento_id=None):
    if data_obj.weekday() not in jornada_vigente(data_obj, departamento_id).dias_trabalho:
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
    Verifica o intervalo interjornada mínimo (parâmetro da TI; CLT: 11h).
    """
    dt_saida = datetime.strptime(f"{data_anterior} {hora_saida}", "%d/%m/%Y %H:%M:%S")
    dt_entrada = datetime.strptime(f"{data_atual} {hora_entrada}", "%d/%m/%Y %H:%M:%S")
    minimo = jornada_vigente(dt_entrada.date()).interjornada_min
    return (dt_entrada - dt_saida) >= timedelta(minutes=minimo)

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
    # Ao excluir um usuário o log é preservado (Portaria 671): o banco zera o
    # vínculo (ON DELETE SET NULL) e o nome do autor fica em ``usuario_nome``,
    # gravado no momento da ação.
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id', ondelete='SET NULL'), nullable=True)
    usuario_nome = db.Column(db.String(100), nullable=True)
    acao = db.Column(db.String(200), nullable=False)
    entidade_id = db.Column(db.Integer, nullable=True)
    data_criacao = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

    usuario = db.relationship("Usuario", backref=db.backref("logs", passive_deletes=True))


class TentativaLogin(db.Model):
    """Falha de login por conta (hash do e-mail), no banco para valer entre
    workers e reinícios. Vale também para e-mails inexistentes, então o
    bloqueio não revela quais contas existem."""
    __tablename__ = "tentativa_login"
    id = db.Column(db.Integer, primary_key=True)
    email_hash = db.Column(db.String(64), nullable=False, index=True)
    criado_em = db.Column(db.DateTime, nullable=False, index=True,
                          default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

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


DIAS_SEMANA = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]


@dataclass(frozen=True)
class Jornada:
    """Regras de jornada e horas extras (parametrizadas pela TI).

    Os valores padrão reproduzem o comportamento original do sistema
    (8h de segunda a sexta, interjornada de 11h) e os limites da CLT.
    """
    carga_diaria_min: int = 480
    dias_trabalho: tuple = (0, 1, 2, 3, 4)  # 0 = segunda ... 6 = domingo
    tolerancia_marcacao_min: int = 5        # CLT art. 58 §1º: até 5 min por marcação
    tolerancia_diaria_min: int = 10         # ... e até 10 min no dia
    intervalo_minimo_min: int = 60          # CLT art. 71: 1h para jornada > 6h
    interjornada_min: int = 660             # CLT art. 66: 11h entre jornadas
    limite_extras_dia_min: int = 120        # CLT art. 59: até 2h extras por dia
    extra_util_pct: int = 50                # CF art. 7º XVI: no mínimo 50%
    extra_descanso_pct: int = 100           # domingos e feriados
    noturno_ativo: bool = False
    noturno_pct: int = 20                   # CLT art. 73: no mínimo 20%
    horario_entrada_min: int = None         # minutos desde 00:00 (None = sem horário fixo)
    horario_saida_min: int = None
    vigente_desde: date = None
    padrao: bool = field(default=False, compare=False)
    setor: str = field(default=None, compare=False)  # setor com carga própria, se houver

    @property
    def carga_diaria_seg(self):
        return self.carga_diaria_min * 60

    @property
    def carga_diaria_fmt(self):
        h, m = divmod(self.carga_diaria_min, 60)
        return f"{h}h" if not m else f"{h}h{m:02d}"

    @property
    def dias_trabalho_texto(self):
        return ", ".join(DIAS_SEMANA[d] for d in sorted(self.dias_trabalho))

    @property
    def horario_texto(self):
        if self.horario_entrada_min is None or self.horario_saida_min is None:
            return None
        fmt = lambda m: f"{m // 60:02d}:{m % 60:02d}"
        return f"{fmt(self.horario_entrada_min)} às {fmt(self.horario_saida_min)}"


# (campo, rótulo, mínimo, máximo) dos parâmetros numéricos editáveis pela TI.
JORNADA_LIMITES = [
    ("carga_diaria_min", "Carga diária", 60, 720),
    ("tolerancia_marcacao_min", "Tolerância por marcação", 0, 5),
    ("tolerancia_diaria_min", "Tolerância diária", 0, 10),
    ("intervalo_minimo_min", "Intervalo mínimo", 0, 240),
    ("interjornada_min", "Interjornada mínima", 660, 1440),
    ("limite_extras_dia_min", "Limite de extras por dia", 0, 240),
    ("extra_util_pct", "Adicional em dia útil", 50, 200),
    ("extra_descanso_pct", "Adicional em domingo/feriado", 50, 300),
    ("noturno_pct", "Adicional noturno", 20, 100),
]


class ParametroJornada(db.Model):
    """Versão das regras de jornada, válida a partir de ``vigente_desde``.

    Nunca se sobrescreve uma versão antiga com outra data: meses passados
    continuam sendo calculados com a regra que valia na época.
    """
    __tablename__ = "parametro_jornada"
    id = db.Column(db.Integer, primary_key=True)
    vigente_desde = db.Column(db.Date, nullable=False, unique=True)
    carga_diaria_min = db.Column(db.Integer, nullable=False)
    dias_trabalho = db.Column(db.String(20), nullable=False)  # ex.: "0,1,2,3,4"
    tolerancia_marcacao_min = db.Column(db.Integer, nullable=False)
    tolerancia_diaria_min = db.Column(db.Integer, nullable=False)
    intervalo_minimo_min = db.Column(db.Integer, nullable=False)
    interjornada_min = db.Column(db.Integer, nullable=False)
    limite_extras_dia_min = db.Column(db.Integer, nullable=False)
    extra_util_pct = db.Column(db.Integer, nullable=False)
    extra_descanso_pct = db.Column(db.Integer, nullable=False)
    noturno_ativo = db.Column(db.Boolean, nullable=False, default=False)
    noturno_pct = db.Column(db.Integer, nullable=False)
    horario_entrada_min = db.Column(db.Integer, nullable=True)
    horario_saida_min = db.Column(db.Integer, nullable=True)
    alterado_por_nome = db.Column(db.String(100), nullable=True)
    alterado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

    def para_jornada(self):
        return Jornada(
            carga_diaria_min=self.carga_diaria_min,
            dias_trabalho=tuple(int(d) for d in self.dias_trabalho.split(",") if d != ""),
            tolerancia_marcacao_min=self.tolerancia_marcacao_min,
            tolerancia_diaria_min=self.tolerancia_diaria_min,
            intervalo_minimo_min=self.intervalo_minimo_min,
            interjornada_min=self.interjornada_min,
            limite_extras_dia_min=self.limite_extras_dia_min,
            extra_util_pct=self.extra_util_pct,
            extra_descanso_pct=self.extra_descanso_pct,
            noturno_ativo=bool(self.noturno_ativo),
            noturno_pct=self.noturno_pct,
            horario_entrada_min=self.horario_entrada_min,
            horario_saida_min=self.horario_saida_min,
            vigente_desde=self.vigente_desde,
        )


class JornadaSetor(db.Model):
    """Carga horária e dias de trabalho próprios de um setor, por vigência.

    Tolerâncias, intervalos e percentuais de extra continuam vindo da
    jornada geral (``ParametroJornada``).
    """
    __tablename__ = "jornada_setor"
    __table_args__ = (db.UniqueConstraint("departamento_id", "vigente_desde", name="uq_jornada_setor_vigencia"),)
    id = db.Column(db.Integer, primary_key=True)
    departamento_id = db.Column(db.Integer, db.ForeignKey("departamento.id", ondelete="CASCADE"), nullable=False, index=True)
    vigente_desde = db.Column(db.Date, nullable=False)
    carga_diaria_min = db.Column(db.Integer, nullable=False)
    dias_trabalho = db.Column(db.String(20), nullable=False)
    horario_entrada_min = db.Column(db.Integer, nullable=True)  # None = usa o horário da jornada geral
    horario_saida_min = db.Column(db.Integer, nullable=True)
    alterado_por_nome = db.Column(db.String(100), nullable=True)
    alterado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

    departamento = db.relationship("Departamento", backref=db.backref(
        "jornadas", lazy=True, passive_deletes=True, order_by="JornadaSetor.vigente_desde.desc()"))

    @property
    def dias_tupla(self):
        return tuple(int(d) for d in self.dias_trabalho.split(",") if d != "")


JORNADA_PADRAO = Jornada(padrao=True)


class PushInscricao(db.Model):
    """Aparelho/navegador inscrito para receber notificações push."""
    __tablename__ = "push_inscricao"
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint = db.Column(db.Text, nullable=False)
    endpoint_hash = db.Column(db.String(64), nullable=False, unique=True)
    p256dh = db.Column(db.String(255), nullable=False)
    auth = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    criado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))


AFASTAMENTO_TIPOS = {
    "ferias": "Férias",
    "atestado": "Atestado médico",
    "licenca": "Licença",
    "folga": "Folga / abono",
    "outro": "Outro",
}
AFASTAMENTO_ANEXO_MAX = 2 * 1024 * 1024
AFASTAMENTO_ANEXO_TIPOS = {b"%PDF": "application/pdf", b"\xff\xd8\xff": "image/jpeg", b"\x89PNG": "image/png"}


class Afastamento(db.Model):
    """Período em que o colaborador está dispensado do ponto (abonado).

    O anexo (ex.: atestado) fica no banco porque o disco do Heroku é
    temporário. É dado de saúde (LGPD): só o RH acessa e cada acesso é logado.
    """
    __tablename__ = "afastamento"
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id", ondelete="CASCADE"), nullable=False, index=True)
    tipo = db.Column(db.String(20), nullable=False)
    data_inicio = db.Column(db.Date, nullable=False)
    data_fim = db.Column(db.Date, nullable=False)
    observacao = db.Column(db.String(500), nullable=True)
    anexo_nome = db.Column(db.String(255), nullable=True)
    anexo_tipo = db.Column(db.String(50), nullable=True)
    anexo_dados = db.deferred(db.Column(db.LargeBinary, nullable=True))
    criado_por_nome = db.Column(db.String(100), nullable=True)
    criado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))

    usuario = db.relationship("Usuario", backref=db.backref("afastamentos", lazy=True, passive_deletes=True))

    @property
    def rotulo(self):
        return AFASTAMENTO_TIPOS.get(self.tipo, self.tipo)

    @property
    def dias(self):
        return (self.data_fim - self.data_inicio).days + 1


def _afastamentos_cache():
    """{usuario_id: [(inicio, fim, tipo), ...]} — carregado uma vez por contexto."""
    try:
        cache = g.get("_afastamentos")
    except RuntimeError:
        return {}
    if cache is None:
        cache = defaultdict(list)
        for uid, ini, fim, tipo in db.session.query(
            Afastamento.usuario_id, Afastamento.data_inicio, Afastamento.data_fim, Afastamento.tipo
        ).all():
            cache[uid].append((ini, fim, tipo))
        g._afastamentos = cache
    return cache


def _limpar_cache_afastamentos():
    try:
        g.pop("_afastamentos", None)
    except Exception:
        pass


def afastamento_no_dia(usuario_id, data_ref):
    """Tipo do afastamento que cobre a data (ou None)."""
    for ini, fim, tipo in _afastamentos_cache().get(usuario_id, []):
        if ini <= data_ref <= fim:
            return tipo
    return None


class FechamentoMes(db.Model):
    """Mês de apuração fechado pelo RH (trava edições daquele período)."""
    __tablename__ = "fechamento_mes"
    __table_args__ = (db.UniqueConstraint("ano", "mes", name="uq_fechamento_ano_mes"),)
    id = db.Column(db.Integer, primary_key=True)
    ano = db.Column(db.Integer, nullable=False)
    mes = db.Column(db.Integer, nullable=False)
    fechado = db.Column(db.Boolean, nullable=False, default=True)
    fechado_em = db.Column(db.DateTime, nullable=True)
    fechado_por_nome = db.Column(db.String(100), nullable=True)
    reaberto_em = db.Column(db.DateTime, nullable=True)
    reaberto_por_nome = db.Column(db.String(100), nullable=True)
    motivo_reabertura = db.Column(db.String(500), nullable=True)

    @property
    def rotulo(self):
        return f"{MESES_PT[self.mes - 1]}/{self.ano}"


class EspelhoMensal(db.Model):
    """Fotografia imutável do espelho de ponto de um colaborador no fechamento.

    ``hash`` identifica o conteúdo; a ciência guarda o hash que a pessoa viu.
    """
    __tablename__ = "espelho_mensal"
    __table_args__ = (db.UniqueConstraint("fechamento_id", "usuario_id", name="uq_espelho_fechamento_usuario"),)
    id = db.Column(db.Integer, primary_key=True)
    fechamento_id = db.Column(db.Integer, db.ForeignKey("fechamento_mes.id", ondelete="CASCADE"), nullable=False, index=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id", ondelete="CASCADE"), nullable=False, index=True)
    usuario_nome = db.Column(db.String(100), nullable=True)
    dados = db.Column(db.Text, nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    ciencia_status = db.Column(db.String(20), nullable=False, default="pendente")  # pendente | ciente | contestado
    ciencia_em = db.Column(db.DateTime, nullable=True)
    ciencia_ip = db.Column(db.String(64), nullable=True)
    ciencia_user_agent = db.Column(db.String(255), nullable=True)
    ciencia_hash = db.Column(db.String(64), nullable=True)
    comentario = db.Column(db.String(1000), nullable=True)

    fechamento = db.relationship("FechamentoMes", backref=db.backref("espelhos", lazy=True, passive_deletes=True))
    usuario = db.relationship("Usuario")

    @property
    def conteudo(self):
        import json as _json
        return _json.loads(self.dados)


def _meses_fechados():
    """{(ano, mes)} fechados — cache por contexto."""
    try:
        cache = g.get("_meses_fechados")
    except RuntimeError:
        return set()
    if cache is None:
        cache = {(a, m) for a, m in db.session.query(FechamentoMes.ano, FechamentoMes.mes).filter(FechamentoMes.fechado.is_(True)).all()}
        g._meses_fechados = cache
    return cache


def _limpar_cache_fechamento():
    try:
        g.pop("_meses_fechados", None)
    except Exception:
        pass


def mes_fechado(data_ref):
    return (data_ref.year, data_ref.month) in _meses_fechados()


def fechado_no_intervalo(inicio, fim):
    """Primeiro mês fechado que o intervalo toca (ou None)."""
    for ano, mes in sorted(_meses_fechados()):
        ini_m = date(ano, mes, 1)
        fim_m = date(ano, mes, calendar.monthrange(ano, mes)[1])
        if inicio <= fim_m and fim >= ini_m:
            return (ano, mes)
    return None


def msg_mes_fechado(ano, mes):
    return (f"O mês de {MESES_PT[mes - 1]}/{ano} está fechado. Para alterar, o RH precisa "
            f"reabri-lo na aba Fechamento.")


class LembreteEnviado(db.Model):
    """Garante um único envio de cada lembrete por pessoa/dia (mesmo com vários processos)."""
    __tablename__ = "lembrete_enviado"
    __table_args__ = (db.UniqueConstraint("usuario_id", "data", "tipo", name="uq_lembrete_dia_tipo"),)
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id", ondelete="CASCADE"), nullable=False, index=True)
    data = db.Column(db.Date, nullable=False)
    tipo = db.Column(db.String(30), nullable=False)
    enviado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))


def _versoes_jornada():
    """Versões ordenadas da mais nova para a mais antiga (cache por requisição)."""
    try:
        cache = g.get("_versoes_jornada")
    except RuntimeError:
        # Fora de contexto de app: regra padrão.
        return []
    if cache is None:
        # Erros de banco não são engolidos: no PostgreSQL deixariam a
        # transação inválida para o resto da requisição.
        cache = [
            v.para_jornada()
            for v in ParametroJornada.query.order_by(ParametroJornada.vigente_desde.desc()).all()
        ]
        g._versoes_jornada = cache
    return cache


def _versoes_setor():
    """{departamento_id: [(vigente_desde, carga_min, dias, nome_setor), ...]} (mais nova primeiro)."""
    try:
        cache = g.get("_versoes_setor")
    except RuntimeError:
        return {}
    if cache is None:
        cache = defaultdict(list)
        linhas = (
            db.session.query(JornadaSetor, Departamento.nome)
            .join(Departamento, Departamento.id == JornadaSetor.departamento_id)
            .order_by(JornadaSetor.vigente_desde.desc())
            .all()
        )
        for js, nome in linhas:
            cache[js.departamento_id].append((js.vigente_desde, js.carga_diaria_min, js.dias_tupla, nome,
                                              js.horario_entrada_min, js.horario_saida_min))
        g._versoes_setor = cache
    return cache


def _limpar_cache_jornada():
    try:
        g.pop("_versoes_jornada", None)
        g.pop("_versoes_setor", None)
    except Exception:
        pass


def jornada_vigente(data_ref=None, departamento_id=None):
    """Regras válidas na data informada (padrão: hoje).

    Com ``departamento_id``, a carga diária e os dias de trabalho do setor
    (se ele tiver carga própria vigente na data) substituem os gerais.
    """
    if data_ref is None:
        data_ref = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    elif isinstance(data_ref, datetime):
        data_ref = data_ref.date()
    base = JORNADA_PADRAO
    for versao in _versoes_jornada():
        if versao.vigente_desde <= data_ref:
            base = versao
            break
    if departamento_id:
        for desde, carga, dias, nome, entrada, saida in _versoes_setor().get(departamento_id, []):
            if desde <= data_ref:
                horarios = {}
                if entrada is not None and saida is not None:
                    horarios = {"horario_entrada_min": entrada, "horario_saida_min": saida}
                return replace(base, carga_diaria_min=carga, dias_trabalho=dias, setor=nome, **horarios)
    return base

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    # Papéis (acumuláveis): RH opera pessoas e ponto; TI parametriza o sistema.
    is_rh = db.Column(db.Boolean, nullable=False, default=False)
    is_ti = db.Column(db.Boolean, nullable=False, default=False)
    # Coluna legada "is_admin": só lida pela migração que criou os papéis.
    admin_legado = db.Column("is_admin", db.Boolean, default=False)
    email_confirmado = db.Column(db.Boolean, default=False)
    precisa_redefinir_senha = db.Column(db.Boolean, default=False)
    auth_version = db.Column(db.Integer, nullable=False, default=0)
    foto_url = db.Column(db.String(255), nullable=True)
    departamento_id = db.Column(db.Integer, db.ForeignKey('departamento.id'), nullable=True)
    tipo_contrato = db.Column(db.String(10), nullable=False, default="CLT")
    cpf = db.Column(db.String(11), nullable=True, unique=True, index=True)  # só dígitos
    # Isenção do raio do local de trabalho (ex.: administrador, trabalho externo); só a TI marca.
    ponto_fora_do_raio = db.Column(db.Boolean, nullable=False, default=False)
    data_cadastro = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    pontos = db.relationship("RegistroPonto", backref="usuario", lazy=True)
    solicitacoes = db.relationship("SolicitacaoCorrecao", backref="usuario", lazy=True)
    security_tokens = db.relationship("SecurityToken", back_populates="usuario", lazy=True, cascade="all, delete-orphan")
    rostos = db.relationship("RostoCadastrado", lazy=True, cascade="all, delete-orphan", passive_deletes=True)

    @property
    def tem_gestao(self):
        """Acessa o painel de gestão (RH e/ou TI)."""
        return bool(self.is_rh or self.is_ti)

    @property
    def papeis_texto(self):
        return " + ".join(p for p, on in (("RH", self.is_rh), ("TI", self.is_ti)) if on) or "Colaborador"

    def get_reset_token(self, expires_sec=None):
        return issue_security_token(self.id, SecurityToken.PURPOSE_RESET, expires_sec or app.config["RESET_TOKEN_TTL_SECONDS"])[0]

    @staticmethod
    def verify_reset_token(token):
        return peek_security_token(token, SecurityToken.PURPOSE_RESET)


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
    if purpose not in {SecurityToken.PURPOSE_RESET, SecurityToken.PURPOSE_INVITE}:
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


def _rate_limit(name, ident=None):
    if not app.config.get("RATE_LIMIT_ENABLED", True):
        return
    limit, window = app.config["RATE_LIMITS"].get(name, (10, 300))
    key = (name, ident if ident is not None else (request.remote_addr or "unknown"))
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
    if not (expected and isinstance(supplied, str) and supplied):
        return False
    # Bytes: compare_digest recusa str com caracteres não ASCII (dava 500).
    return secrets.compare_digest(expected.encode(), supplied.encode())


@app.before_request
def forcar_https():
    if app.config.get("FORCE_HTTPS") and not request.is_secure:
        return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.before_request
def enforce_csrf_and_rate_limits():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _csrf_is_valid():
            app.logger.info("CSRF recusado em %s %s", request.method, request.path)
            if request.path.startswith("/api/") or request.is_json:
                abort(403, description="Token CSRF inválido ou ausente.")
            # Formulário enviado de uma página desatualizada (sessão renovada,
            # login em outra aba etc.): explica e oferece voltar, sem executar nada.
            voltar = _internal_referrer_path(url_for("index") if current_user.is_authenticated else url_for("login"))
            return render_template("erro_csrf.html", voltar=voltar), 403
    rate_endpoint = request.endpoint
    # Só tentativas (POST) contam: abrir a tela de login não pode gastar o
    # limite de um escritório inteiro que sai pelo mesmo IP.
    if request.method != "POST" and rate_endpoint in {
        "login", "forgot_password", "reset_password", "definir_senha_usuario",
    }:
        return None
    if rate_endpoint in {
        "login", "forgot_password", "upload_foto_perfil", "reset_password",
        "definir_senha_usuario", "api_localizacao",
    }:
        _rate_limit("upload" if rate_endpoint == "upload_foto_perfil" else rate_endpoint)


_LIBERADO_NA_TROCA_DE_SENHA = {"redefinir_senha_forca", "logout", "static", "service_worker", "manifesto_pwa"}


@app.before_request
def exigir_troca_de_senha():
    """Com a troca obrigatória pendente, nada além da própria troca funciona."""
    if request.endpoint in _LIBERADO_NA_TROCA_DE_SENHA or not current_user.is_authenticated:
        return None
    if not current_user.precisa_redefinir_senha:
        return None
    if request.path.startswith("/api/") or request.is_json:
        return jsonify(erro="Troque sua senha antes de continuar."), 403
    return redirect(url_for("redefinir_senha_forca"))


def csp_nonce():
    """Nonce da requisição para os <script> inline (CSP sem 'unsafe-inline')."""
    if "csp_nonce" not in g:
        g.csp_nonce = secrets.token_urlsafe(18)
    return g.csp_nonce


# Só estes arquivos do CDN podem rodar (o jsDelivr serve qualquer pacote npm
# ou repositório do GitHub, então liberar o domínio inteiro não protege).
# As tags nos templates também levam o hash SRI de cada arquivo.
_CDN_SCRIPTS = (
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js",
    "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js",
    "https://cdn.jsdelivr.net/npm/gridstack@12.6.0/dist/gridstack-all.js",
)


@app.context_processor
def inject_security_context():
    return {"csrf_token": csrf_token, "csp_nonce": csp_nonce}


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # Só a tela do quiosque usa a câmera e o detector de rosto (WebAssembly,
    # servido pelo próprio app); no resto do sistema os dois continuam barrados.
    eh_quiosque = request.endpoint == "quiosque"
    # A TI usa a câmera no painel para cadastrar rostos do reconhecimento facial.
    camera_ti = (request.path.startswith("/admin") and current_user.is_authenticated
                 and bool(getattr(current_user, "is_ti", False)))
    response.headers.setdefault(
        "Permissions-Policy",
        f"camera=({'self' if eh_quiosque or camera_ti else ''}), microphone=(), geolocation=(self), screen-wake-lock=(self)",
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    wasm = " 'wasm-unsafe-eval'" if eh_quiosque else ""
    img_blob = " blob:" if eh_quiosque else ""  # prévia da foto tirada
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        f"form-action 'self'; script-src 'self' 'nonce-{csp_nonce()}'{wasm} {' '.join(_CDN_SCRIPTS)}; "
        "script-src-attr 'none'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        f"img-src 'self' data:{img_blob}; connect-src 'self' https://api.bigdatacloud.net",
    )
    if app.config["SESSION_COOKIE_SECURE"] and request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # Bibliotecas e modelos do quiosque (~22 MB) não mudam entre versões: o
    # aparelho guarda por 30 dias em vez de revalidar a cada abertura.
    # Ao atualizar algum desses arquivos, troque o nome da pasta/arquivo.
    if request.path.startswith("/static/quiosque/") and response.status_code == 200:
        response.headers["Cache-Control"] = "public, max-age=2592000, immutable"
    if request.endpoint in {
        "login", "forgot_password", "reset_password", "definir_senha_usuario",
        "logout", "redefinir_senha_forca", "alterar_senha",
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
    # Onde a batida foi feita pelo app (quando o raio do local de trabalho está ativo).
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    precisao_m = db.Column(db.Integer, nullable=True)
    distancia_m = db.Column(db.Integer, nullable=True)  # até o local de trabalho, no momento da batida
    # Foto tirada no quiosque (comprovante); sai junto com o registro.
    foto = db.relationship("FotoPonto", uselist=False, lazy=True, cascade="all, delete-orphan", passive_deletes=True)


class FotoPonto(db.Model):
    """Foto do rosto tirada no quiosque no momento da batida (comprovante).
    Guardada pelo mesmo prazo do registro; o banco apaga junto com ele."""
    __tablename__ = "foto_ponto"
    id = db.Column(db.Integer, primary_key=True)
    registro_id = db.Column(db.Integer, db.ForeignKey("registro_ponto.id", ondelete="CASCADE"),
                            nullable=False, unique=True, index=True)
    dados = db.Column(db.LargeBinary, nullable=False)
    mime = db.Column(db.String(30), nullable=False, default="image/jpeg")
    criado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))


class RostoCadastrado(db.Model):
    """Assinatura facial (descritor de 128 números, float32) de um colaborador,
    cadastrada pela TI para o reconhecimento no quiosque. Não guarda a foto.
    Biometria é dado sensível (LGPD): só com consentimento, registrado aqui."""
    __tablename__ = "rosto_cadastrado"
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id", ondelete="CASCADE"), nullable=False, index=True)
    descritor = db.Column(db.LargeBinary, nullable=False)  # 128 x float32 = 512 bytes
    consentimento_em = db.Column(db.DateTime, nullable=False)
    criado_por_nome = db.Column(db.String(100), nullable=True)
    criado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))


class QuiosqueDispositivo(db.Model):
    """Tablet autorizado pela TI a funcionar como quiosque de ponto.
    Não é uma conta: o aparelho guarda um token opaco (só o hash fica aqui)."""
    __tablename__ = "quiosque_dispositivo"
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    criado_em = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/Sao_Paulo")))
    criado_por_nome = db.Column(db.String(100), nullable=True)
    ultimo_uso_em = db.Column(db.DateTime, nullable=True)

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

def _papel_required(checar, mensagem):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not checar(current_user):
                flash(mensagem, "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# RH: colaboradores, ponto, correções, relatórios. TI: parâmetros, feriados,
# departamentos, acessos e logs. ``gestao_required``: telas comuns aos dois.
rh_required = _papel_required(lambda u: u.is_rh, "Acesso permitido apenas ao RH.")
ti_required = _papel_required(lambda u: u.is_ti, "Acesso permitido apenas à TI.")
gestao_required = _papel_required(lambda u: u.tem_gestao, "Acesso permitido apenas ao RH e à TI.")

def _migrar_log_auditoria(inspector):
    """Logs de auditoria sobrevivem à exclusão do usuário (Portaria 671).

    Garante ``usuario_nome``, ``usuario_id`` anulável e FK com
    ON DELETE SET NULL. Idempotente: só executa DDL quando algo falta.
    Só o PostgreSQL (Supabase) é usado em produção; em outros bancos (ex.: o
    SQLite dos testes) o ``create_all`` já cria a tabela no formato novo.
    """
    from sqlalchemy import text

    if db.engine.name != "postgresql":
        return

    colunas = {c["name"]: c for c in inspector.get_columns("log_auditoria")}
    fks = [
        fk for fk in inspector.get_foreign_keys("log_auditoria")
        if fk.get("referred_table") == "usuario" and fk.get("constrained_columns") == ["usuario_id"]
    ]
    fk_ok = bool(fks) and all(
        (fk.get("options") or {}).get("ondelete", "").upper() == "SET NULL" for fk in fks
    )
    precisa_backfill = "usuario_nome" not in colunas

    if precisa_backfill:
        db.session.execute(text("ALTER TABLE log_auditoria ADD COLUMN usuario_nome VARCHAR(100)"))
    if not colunas["usuario_id"]["nullable"]:
        db.session.execute(text("ALTER TABLE log_auditoria ALTER COLUMN usuario_id DROP NOT NULL"))
    if not fk_ok:
        for fk in fks:
            db.session.execute(text(f'ALTER TABLE log_auditoria DROP CONSTRAINT "{fk["name"]}"'))
        db.session.execute(text(
            "ALTER TABLE log_auditoria ADD CONSTRAINT log_auditoria_usuario_id_fkey "
            "FOREIGN KEY (usuario_id) REFERENCES usuario(id) ON DELETE SET NULL"
        ))

    if precisa_backfill:
        db.session.execute(text(
            "UPDATE log_auditoria SET usuario_nome = "
            "(SELECT nome FROM usuario WHERE usuario.id = log_auditoria.usuario_id) "
            "WHERE usuario_nome IS NULL AND usuario_id IS NOT NULL"
        ))


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
        ("is_rh", "ALTER TABLE usuario ADD COLUMN is_rh BOOLEAN NOT NULL DEFAULT FALSE"),
        ("is_ti", "ALTER TABLE usuario ADD COLUMN is_ti BOOLEAN NOT NULL DEFAULT FALSE"),
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
    if "is_rh" not in colunas_usuario and "is_ti" not in colunas_usuario:
        # Papéis acabaram de ser criados: administradores antigos recebem RH + TI
        # para ninguém perder acesso; a TI ajusta depois na tela de usuários.
        db.session.execute(text("UPDATE usuario SET is_rh = TRUE, is_ti = TRUE WHERE is_admin = TRUE"))
    if "data_cadastro" not in colunas_usuario:
        data_type = "TIMESTAMP" if db.engine.name == "postgresql" else "DATETIME"
        db.session.execute(text(f"ALTER TABLE usuario ADD COLUMN data_cadastro {data_type}"))
        db.session.execute(text("UPDATE usuario SET data_cadastro = CURRENT_TIMESTAMP"))
    if "cpf" not in colunas_usuario:
        # CPF (só dígitos) para identificar a pessoa no quiosque; único quando preenchido.
        db.session.execute(text("ALTER TABLE usuario ADD COLUMN cpf VARCHAR(11)"))
    db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_usuario_cpf ON usuario (cpf)"))
    if "ponto_fora_do_raio" not in colunas_usuario:
        db.session.execute(text("ALTER TABLE usuario ADD COLUMN ponto_fora_do_raio BOOLEAN NOT NULL DEFAULT FALSE"))

    colunas_ponto = [c["name"] for c in inspector.get_columns("registro_ponto")]
    if "foi_ajustado" not in colunas_ponto:
        db.session.execute(text("ALTER TABLE registro_ponto ADD COLUMN foi_ajustado BOOLEAN DEFAULT FALSE"))
    tipo_real = "DOUBLE PRECISION" if db.engine.name == "postgresql" else "REAL"
    for coluna, ddl in (
        ("latitude", f"ALTER TABLE registro_ponto ADD COLUMN latitude {tipo_real}"),
        ("longitude", f"ALTER TABLE registro_ponto ADD COLUMN longitude {tipo_real}"),
        ("precisao_m", "ALTER TABLE registro_ponto ADD COLUMN precisao_m INTEGER"),
        ("distancia_m", "ALTER TABLE registro_ponto ADD COLUMN distancia_m INTEGER"),
    ):
        if coluna not in colunas_ponto:
            db.session.execute(text(ddl))
    colunas_solicitacao = [c["name"] for c in inspector.get_columns("solicitacao_correcao")]
    if "hora_original" not in colunas_solicitacao:
        db.session.execute(text("ALTER TABLE solicitacao_correcao ADD COLUMN hora_original VARCHAR(8)"))
    colunas_feriado = [c["name"] for c in inspector.get_columns("feriado")]
    if "fonte" not in colunas_feriado:
        db.session.execute(text("ALTER TABLE feriado ADD COLUMN fonte VARCHAR(20) DEFAULT 'manual'"))

    _migrar_log_auditoria(inspector)

    # Notificações gravadas: bancos criados por versões antigas não tinham
    # título/tipo/link (o "Enviar Lembrete" falhava ao gravar).
    if "notificacao" in inspector.get_table_names():
        colunas_notif = [c["name"] for c in inspector.get_columns("notificacao")]
        for coluna, ddl in (
            ("titulo", "ALTER TABLE notificacao ADD COLUMN titulo VARCHAR(150) DEFAULT 'Aviso Geral'"),
            ("tipo", "ALTER TABLE notificacao ADD COLUMN tipo VARCHAR(50) DEFAULT 'info'"),
            ("link", "ALTER TABLE notificacao ADD COLUMN link VARCHAR(255)"),
        ):
            if coluna not in colunas_notif:
                db.session.execute(text(ddl))

    # Horários de entrada/saída (lembretes de ponto).
    for tabela in ("parametro_jornada", "jornada_setor"):
        if tabela in inspector.get_table_names():
            colunas = [c["name"] for c in inspector.get_columns(tabela)]
            for coluna in ("horario_entrada_min", "horario_saida_min"):
                if coluna not in colunas:
                    db.session.execute(text(f"ALTER TABLE {tabela} ADD COLUMN {coluna} INTEGER"))

    db.session.execute(text("UPDATE usuario SET auth_version = COALESCE(auth_version, 0)"))
    db.session.commit()
    try:
        _sincronizar_feriados_lib()
    except Exception as exc:
        app.logger.warning("Falha ao sincronizar feriados na inicialização: %s", exc)



@app.cli.command("generate-secret")
def generate_secret():
    """Gera uma chave secreta aleatória segura."""
    import secrets
    key = secrets.token_hex(32)
    click.echo("\n" + "="*40)
    click.echo("SUA NOVA SECRET_KEY GERADA:")
    click.echo("="*40)
    click.echo(key)
    click.echo("="*40)
    click.echo("Copie e cole este valor nas configurações do seu servidor.\n")


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
        is_rh=True,
        is_ti=True,
        email_confirmado=True,
        precisa_redefinir_senha=False,
    )
    db.session.add(user)
    db.session.commit()
    click.echo(f"Administrador (RH + TI) criado: {email}")


@app.cli.command("redefinir-senha")
@click.option("--email", prompt=True)
@click.option("--senha", prompt="Senha provisória", hide_input=True, confirmation_prompt=True)
def redefinir_senha_cli(email, senha):
    """Emergência: troca a senha de qualquer conta (ex.: toda a TI esqueceu).

    Só roda com acesso ao servidor (heroku run). A pessoa é obrigada a
    escolher uma senha nova no próximo acesso, e a troca vai para o log."""
    email = email.strip().lower()
    user = Usuario.query.filter(db.func.lower(Usuario.email) == email).first()
    if not user:
        raise click.ClickException("Nenhuma conta com este e-mail.")
    problem = _password_problem(senha)
    if problem:
        raise click.ClickException(problem)
    _aplicar_senha(user, senha, exigir_troca=True)
    db.session.commit()
    registrar_log(None, f"Senha de {user.nome} redefinida por comando no servidor (emergência)", user.id)
    click.echo(f"Senha de {user.nome} ({email}) redefinida. Troca obrigatória no próximo acesso; sessões abertas encerradas.")


# ==========================================
#         SISTEMA DE NOTIFICAÇÕES
# ==========================================

PONTOS_PERMITIDOS = ["Entrada", "Saída"]


def _data_iso(valor):
    """AAAA-MM-DD vinda de filtro; valor inválido vira None (sem erro 500)."""
    try:
        return datetime.strptime(valor, "%Y-%m-%d").date() if valor else None
    except ValueError:
        return None
_HORA_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$")


def _hora_valida(valor):
    """Normaliza HH:MM ou HH:MM:SS para HH:MM:SS; devolve None se inválida."""
    valor = (valor or "").strip()
    if not _HORA_RE.match(valor):
        return None
    return valor if len(valor) == 8 else f"{valor}:00"

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

# ==========================================
#   APURAÇÃO DE PONTO (extras pagas, CLT)
# ==========================================
@dataclass
class ApuracaoDia:
    """Resultado de um dia para um colaborador (tempos em segundos)."""
    data: date
    tipo_dia: str                      # util | descanso | domingo | feriado | afastado
    batidas: list = field(default_factory=list)   # [(tipo, "HH:MM:SS")] em ordem
    trabalhado: int = 0
    esperado: int = 0
    extra_50: int = 0
    extra_100: int = 0
    atraso: int = 0                    # atraso/saída antecipada em dia trabalhado
    falta: bool = False
    falta_seg: int = 0
    noturno: int = 0                   # tempo real entre 22h e 5h
    incompleto: bool = False
    em_aberto: bool = False
    futuro: bool = False
    tolerado: bool = False             # diferença absorvida pela tolerância
    afastamento: str = None
    alertas: list = field(default_factory=list)

    @property
    def extras(self):
        return self.extra_50 + self.extra_100

    @property
    def situacao(self):
        if self.futuro:
            return "-"
        if self.afastamento:
            return AFASTAMENTO_TIPOS.get(self.afastamento, self.afastamento).upper()
        if self.em_aberto:
            return "Em Aberto"
        if self.falta:
            return "FALTA"
        if self.incompleto:
            return "INCOMPLETO"
        partes = []
        if self.tipo_dia == "feriado":
            partes.append("Feriado")
        elif self.tipo_dia == "domingo":
            partes.append("Domingo")
        elif self.tipo_dia == "descanso" and self.batidas:
            partes.append("Folga")
        if self.tolerado:
            partes.append("Tolerância")
        partes.extend(self.alertas)
        return " · ".join(partes) if partes else ("Ok" if self.batidas else "")


def fmt_hhmm(segundos, sinal=False):
    """Segundos -> 'HH:MM' (com '+'/'-' opcional)."""
    seg = int(segundos or 0)
    neg = seg < 0
    h, m = divmod(abs(seg) // 60, 60)
    txt = f"{h:02d}:{m:02d}"
    if sinal:
        txt = ("-" if neg else "+") + txt
    return txt


def _minutos_do_dia(hora):
    t = _parse_hora(hora)
    return None if t is None else t.hour * 60 + t.minute + t.second / 60


def _sobreposicao_noturna(ini_min, fim_min):
    """Minutos de [ini, fim) dentro de 00:00–05:00 e 22:00–24:00."""
    total = 0
    for a, b in ((0, 300), (1320, 1440)):
        total += max(0, min(fim_min, b) - max(ini_min, a))
    return total


def apurar_dia(usuario, data_ref, batidas, hoje=None, saida_anterior=None):
    """Apura um dia. ``batidas``: [(tipo, hora)] do dia (qualquer ordem).

    ``saida_anterior``: datetime da última saída do dia anterior (interjornada).
    """
    hoje = hoje or datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    dep = usuario.departamento_id
    j = jornada_vigente(data_ref, dep)
    afast = afastamento_no_dia(usuario.id, data_ref)
    util = eh_dia_util(data_ref, dep)
    trabalha_no_dia = data_ref.weekday() in j.dias_trabalho
    if afast:
        tipo_dia = "afastado"
    elif util:
        tipo_dia = "util"
    elif trabalha_no_dia:
        tipo_dia = "feriado"          # dia de trabalho, mas feriado
    elif data_ref.weekday() == 6:
        tipo_dia = "domingo"
    else:
        tipo_dia = "descanso"

    seq = sorted(((h or "", t) for t, h in batidas if t in PONTOS_PERMITIDOS))
    ap = ApuracaoDia(data=data_ref, tipo_dia=tipo_dia, batidas=[(t, h) for h, t in seq], afastamento=afast)

    # Pares Entrada -> Saída em ordem; soma trabalhado, noturno e intervalos.
    pares, aberta = [], None
    for h, t in seq:
        m = _minutos_do_dia(h)
        if m is None:
            continue
        if t == "Entrada":
            aberta = m
        elif t == "Saída" and aberta is not None:
            if m > aberta:
                pares.append((aberta, m))
            aberta = None
    ap.trabalhado = int(sum((b - a) * 60 for a, b in pares))
    ap.noturno = int(sum(_sobreposicao_noturna(a, b) * 60 for a, b in pares))
    ultima_aberta = bool(seq) and seq[-1][1] == "Entrada"

    if getattr(usuario, "tipo_contrato", "CLT") == "PJ":
        ap.futuro = data_ref > hoje
        ap.em_aberto = data_ref == hoje and ultima_aberta
        return ap
    if data_ref > hoje:
        ap.futuro = True
        return ap
    if data_ref == hoje and (not seq or ultima_aberta):
        ap.em_aberto = True
        return ap
    if afast:
        return ap
    if not seq:
        if tipo_dia == "util":
            ap.falta = True
            ap.esperado = ap.falta_seg = j.carga_diaria_seg
        return ap
    if ultima_aberta:
        ap.incompleto = True
        ap.alertas.append("Entrada sem saída")
        return ap

    if tipo_dia == "util":
        ap.esperado = j.carga_diaria_seg
        diff = ap.trabalhado - ap.esperado
        dentro = abs(diff) <= j.tolerancia_diaria_min * 60
        if dentro and j.horario_entrada_min is not None and j.horario_saida_min is not None and pares:
            var_e = abs(pares[0][0] - j.horario_entrada_min)
            var_s = abs(pares[-1][1] - j.horario_saida_min)
            dentro = (var_e <= j.tolerancia_marcacao_min and var_s <= j.tolerancia_marcacao_min
                      and var_e + var_s <= j.tolerancia_diaria_min)
        if diff == 0:
            pass
        elif dentro:
            ap.tolerado = True
        elif diff > 0:
            ap.extra_50 = diff
        else:
            ap.atraso = -diff
    else:
        # Folga/domingo/feriado trabalhado: tudo é extra.
        if tipo_dia in ("domingo", "feriado"):
            ap.extra_100 = ap.trabalhado
        else:
            ap.extra_50 = ap.trabalhado

    # Alertas legais
    if ap.extras > j.limite_extras_dia_min * 60 and j.limite_extras_dia_min > 0:
        ap.alertas.append(f"Extras acima de {fmt_hhmm(j.limite_extras_dia_min * 60)}")
    if ap.trabalhado > 6 * 3600 and j.intervalo_minimo_min > 0:
        intervalos = [pares[i + 1][0] - pares[i][1] for i in range(len(pares) - 1)]
        maior = max(intervalos) if intervalos else 0
        if maior < j.intervalo_minimo_min:
            ap.alertas.append("Sem intervalo" if not intervalos else f"Intervalo de {int(maior)} min")
    if saida_anterior is not None and pares:
        entrada_dt = datetime.combine(data_ref, datetime.min.time()) + timedelta(minutes=pares[0][0])
        if entrada_dt - saida_anterior < timedelta(minutes=j.interjornada_min):
            ap.alertas.append("Interjornada curta")
    return ap


def apurar_periodo(usuario, inicio, fim, hoje=None):
    """Apura dia a dia e soma os totais do período."""
    hoje = hoje or datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    batidas = defaultdict(list)
    # Inclui o dia anterior ao início para a interjornada do primeiro dia.
    for r in RegistroPonto.query.filter_by(usuario_id=usuario.id).all():
        try:
            d = datetime.strptime(r.data, "%d/%m/%Y").date()
        except (TypeError, ValueError):
            continue
        if inicio - timedelta(days=1) <= d <= fim:
            batidas[d].append((r.tipo, r.hora))

    def ultima_saida(d):
        saidas = sorted(h for t, h in batidas.get(d, []) if t == "Saída" and h)
        if not saidas:
            return None
        m = _minutos_do_dia(saidas[-1])
        return None if m is None else datetime.combine(d, datetime.min.time()) + timedelta(minutes=m)

    dias = []
    d = inicio
    while d <= fim:
        dias.append(apurar_dia(usuario, d, batidas.get(d, []), hoje=hoje, saida_anterior=ultima_saida(d - timedelta(days=1))))
        d += timedelta(days=1)

    j_atual = jornada_vigente(min(fim, hoje), usuario.departamento_id)
    tot = {
        "trabalhado": sum(x.trabalhado for x in dias),
        "extra_50": sum(x.extra_50 for x in dias),
        "extra_100": sum(x.extra_100 for x in dias),
        "atraso": sum(x.atraso for x in dias),
        "falta_seg": sum(x.falta_seg for x in dias),
        "faltas_dias": sum(1 for x in dias if x.falta),
        "afastados_dias": sum(1 for x in dias if x.afastamento and x.tipo_dia == "afastado" and eh_dia_util(x.data, usuario.departamento_id)),
        "incompletos": sum(1 for x in dias if x.incompleto),
        "noturno": sum(x.noturno for x in dias),
        "dias_acima_limite": sum(1 for x in dias if any(a.startswith("Extras acima") for a in x.alertas)),
        "alertas": sum(1 for x in dias if x.alertas and not x.incompleto),
        "noturno_ativo": j_atual.noturno_ativo,
        "noturno_pct": j_atual.noturno_pct,
        "extra_util_pct": j_atual.extra_util_pct,
        "extra_descanso_pct": j_atual.extra_descanso_pct,
    }
    # Hora noturna reduzida (CLT art. 73 §1º): 52min30s valem 1 hora.
    tot["noturno_ficto"] = int(tot["noturno"] * 60 / 52.5)
    return dias, tot


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

    # Setor do usuário: define carga e dias de trabalho nas regras abaixo.
    _usuario_notif = db.session.get(Usuario, user_id)
    dep_id = _usuario_notif.departamento_id if _usuario_notif else None

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
            if eh_dia_util(curr, dep_id) and curr not in pontos_por_data and not afastamento_no_dia(user_id, curr):
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
            if janela_inicio <= d_obj < hoje and eh_dia_util(d_obj, dep_id) and not afastamento_no_dia(user_id, d_obj):
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
        jornada_hoje = jornada_vigente(hoje, dep_id)
        agora_min = datetime.now(ZoneInfo("America/Sao_Paulo"))
        agora_min = agora_min.hour * 60 + agora_min.minute
        ja_no_horario = jornada_hoje.horario_entrada_min is None or agora_min >= jornada_hoje.horario_entrada_min
        if eh_dia_util(hoje, dep_id) and ja_no_horario and not afastamento_no_dia(user_id, hoje):
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

    # ── 6. Avisos gravados (lembrete da administração, "esqueceu a entrada"...) ──
    # Ficam até a pessoa abrir/marcar como lido; mostrados antes dos calculados.
    limite_avisos = datetime.now(ZoneInfo("America/Sao_Paulo")) - timedelta(days=30)
    gravados = (Notificacao.query
                .filter(Notificacao.usuario_id == user_id, Notificacao.lida.is_(False),
                        Notificacao.data_criacao >= limite_avisos.replace(tzinfo=None))
                .order_by(Notificacao.id.desc()).limit(10).all())
    notificacoes = [{
        "id": f"aviso_{n.id}",
        "db_id": n.id,
        "tipo": n.tipo if n.tipo in ("info", "warning", "danger", "success") else "info",
        "titulo": n.titulo,
        "mensagem": n.mensagem,
        "link": url_for("abrir_notificacao", id=n.id),
    } for n in gravados] + notificacoes

    # ── 7. Salva no cache ──
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

LOGIN_FALHAS_MAX = 5
LOGIN_BLOQUEIO_MIN = 15


def _conta_bloqueada(email_hash):
    desde = _local_now() - timedelta(minutes=LOGIN_BLOQUEIO_MIN)
    return TentativaLogin.query.filter(
        TentativaLogin.email_hash == email_hash, TentativaLogin.criado_em > desde
    ).count() >= LOGIN_FALHAS_MAX


def _registrar_falha_login(email_hash):
    # Limpeza barata das falhas antigas a cada nova falha.
    TentativaLogin.query.filter(TentativaLogin.criado_em < _local_now() - timedelta(days=1)).delete()
    db.session.add(TentativaLogin(email_hash=email_hash, criado_em=_local_now()))
    db.session.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    # Tablet autorizado como quiosque: o app abre direto na tela do quiosque
    # (também quando o ícone da tela inicial abre "/").
    if request.method == "GET" and _quiosque_atual() is not None:
        return redirect(url_for("quiosque"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]
        senha = request.form.get("senha", "")
        email_hash = hashlib.sha256(email.encode()).hexdigest()
        if _conta_bloqueada(email_hash):
            registrar_log(None, f"Login bloqueado por excesso de tentativas: {email} (IP {request.remote_addr})")
            flash(f"Muitas tentativas de login para esta conta. Aguarde {LOGIN_BLOQUEIO_MIN} minutos "
                  "ou peça ao RH para definir uma nova senha.", "danger")
            return render_template("login.html", email=email), 429
        user = Usuario.query.filter(db.func.lower(Usuario.email) == email).first()
        password_hash = user.senha_hash if user is not None else DUMMY_PASSWORD_HASH
        valid = check_password_hash(password_hash, senha)
        if valid and user is not None and user.email_confirmado:
            TentativaLogin.query.filter_by(email_hash=email_hash).delete()
            # Rotaciona o identificador da sessão antes de autenticar para
            # impedir fixação de sessão.
            session.clear()
            login_user(user)
            session.permanent = True
            session["_auth_version"] = int(user.auth_version or 0)
            registrar_log(user.id, f"Entrou no sistema (IP {request.remote_addr})", user.id)
            if user.precisa_redefinir_senha:
                flash("Você precisa redefinir sua senha no primeiro acesso.", "info")
                return redirect(url_for("redefinir_senha_forca"))
            return redirect(url_for("index"))
        _registrar_falha_login(email_hash)
        registrar_log(user.id if user else None,
                      f"Falha de login: {email} (IP {request.remote_addr})", user.id if user else None)
        # A mesma resposta para e-mail inexistente, senha inválida ou e-mail
        # ainda não confirmado evita enumeração de contas.
        flash("E-mail ou senha incorretos.", "danger")
        return render_template("login.html", email=email)

    return render_template("login.html")

_MSG_CADASTRO_FECHADO = "O cadastro é feito pelo administrador da empresa. Peça seu acesso a ele."


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    """Autocadastro desativado: contas são criadas só pelo administrador."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    flash(_MSG_CADASTRO_FECHADO, "info")
    return redirect(url_for("login"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    registrar_log(current_user.id, "Saiu do sistema", current_user.id)
    logout_user()
    session.clear()
    flash("Você saiu da conta.", "info")
    return redirect(url_for("login"))

@app.route("/redefinir_senha_forca", methods=["GET", "POST"])
@login_required
def redefinir_senha_forca():
    # Só existe para a troca obrigatória: sem isso, uma sessão roubada
    # trocaria a senha sem informar a atual (o que /alterar_senha exige).
    if not current_user.precisa_redefinir_senha:
        return redirect(url_for("index"))
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
    "parametros": "admin_parametros",
    "afastamentos": "admin_afastamentos",
    "fechamento": "admin_fechamento",
}

# Abas do painel restritas a um papel (as demais são comuns ao RH e à TI).
_PAPEL_POR_ABA = {"historico": "rh", "solicitacoes": "rh", "logs": "ti", "parametros": "ti", "afastamentos": "rh", "fechamento": "rh"}


def _redirect_admin(view_name, ancora=None):
    """Volta à aba que originou a ação, preservando seus filtros.

    ``ancora`` rola a página até a seção editada (ex.: ``setores``).
    """
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
    if ancora:
        target = f"{target}#{ancora}"
    return redirect(target)


@app.route("/admin/lancar-ponto-manual", methods=["POST"])
@rh_required
def admin_lancar_ponto_manual():
    usuario_id = request.form.get("usuario_id")
    data_raw = request.form.get("data")        # esperada no formato YYYY-MM-DD
    tipo = request.form.get("tipo")
    hora_raw = request.form.get("hora")        # esperada no formato HH:MM
    justificativa = request.form.get("justificativa", "").strip()

    if not usuario_id or not data_raw or not tipo or not hora_raw:
        flash("Todos os campos obrigatórios devem ser preenchidos.", "danger")
        return _redirect_admin("painel")

    try:
        usuario_alvo = db.session.get(Usuario, int(usuario_id))
    except (TypeError, ValueError):
        usuario_alvo = None
    if not usuario_alvo:
        flash("Usuário não encontrado.", "danger")
        return _redirect_admin("painel")
    if usuario_alvo.id == current_user.id:
        flash("Você não pode lançar ponto para si mesmo. Peça a outra pessoa do RH ou use a solicitação de correção.", "danger")
        return _redirect_admin("painel")

    if tipo not in PONTOS_PERMITIDOS:
        flash("Tipo de ponto inválido.", "danger")
        return _redirect_admin("painel")
    hora_formatada = _hora_valida(hora_raw)
    if not hora_formatada:
        flash("Hora inválida.", "danger")
        return _redirect_admin("painel")

    # Formatar data de YYYY-MM-DD para DD/MM/YYYY. Qualquer outro formato é
    # recusado: aceitá-lo pularia a trava de mês fechado.
    try:
        data_obj = datetime.strptime(data_raw, "%Y-%m-%d")
    except ValueError:
        flash("Data inválida.", "danger")
        return _redirect_admin("painel")
    data_formatada = data_obj.strftime("%d/%m/%Y")
    if mes_fechado(data_obj.date()):
        flash(msg_mes_fechado(data_obj.year, data_obj.month), "danger")
        return _redirect_admin("painel")

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
@rh_required
def admin_excluir_ponto(ponto_id):
    """Exclui um registro de ponto (apenas admin/RH). Usado para remover duplicatas."""
    ponto = RegistroPonto.query.get_or_404(ponto_id)
    if ponto.usuario_id == current_user.id:
        flash("Você não pode excluir registros do seu próprio ponto. Peça a outra pessoa do RH.", "danger")
        return _redirect_admin("historico")
    try:
        data_ponto = datetime.strptime(ponto.data, "%d/%m/%Y").date()
    except (TypeError, ValueError):
        data_ponto = None
    if data_ponto and mes_fechado(data_ponto):
        flash(msg_mes_fechado(data_ponto.year, data_ponto.month), "danger")
        return _redirect_admin("historico")
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

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _departamento_do_form(valor):
    """Converte o select de departamento em id válido (ou None)."""
    if not valor or valor == "none":
        return None
    try:
        dep_id = int(valor)
    except (TypeError, ValueError):
        return None
    return dep_id if db.session.get(Departamento, dep_id) else None


def _validar_senha_admin(senha, confirmar):
    """Valida a senha que o administrador digitou para um colaborador."""
    if senha != confirmar:
        return "A confirmação da senha não confere."
    return _password_problem(senha)


def _aplicar_senha(usuario, senha, exigir_troca):
    """Grava nova senha, derruba sessões e invalida links pendentes."""
    usuario.senha_hash = generate_password_hash(senha, method="scrypt")
    usuario.precisa_redefinir_senha = bool(exigir_troca)
    usuario.auth_version = int(usuario.auth_version or 0) + 1
    if usuario.id is not None:
        SecurityToken.query.filter(
            SecurityToken.usuario_id == usuario.id,
            SecurityToken.purpose.in_([SecurityToken.PURPOSE_RESET, SecurityToken.PURPOSE_INVITE]),
            SecurityToken.usado_em.is_(None),
        ).update({"usado_em": _local_now()}, synchronize_session=False)


@app.route("/admin/cadastrar_usuario", methods=["POST"])
@login_required
@rh_required
def admin_cadastrar_usuario():
    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    tipo_contrato = request.form.get("tipo_contrato", "CLT").strip().upper()
    if tipo_contrato not in ("CLT", "PJ"):
        tipo_contrato = "CLT"
    departamento_id = _departamento_do_form(request.form.get("departamento_id"))
    enviar_convite = request.form.get("modo_acesso") == "convite"
    exigir_troca = request.form.get("exigir_troca") == "on"

    if not nome or not email:
        flash("Nome e e-mail são obrigatórios.", "danger")
        return _redirect_admin("usuarios")
    if len(nome) > 100 or len(email) > 100 or not _EMAIL_RE.match(email):
        flash("Informe um nome e um e-mail válidos (até 100 caracteres).", "danger")
        return _redirect_admin("usuarios")
    if Usuario.query.filter(db.func.lower(Usuario.email) == email).first():
        flash(f"Já existe um usuário com o e-mail {email}.", "danger")
        return _redirect_admin("usuarios")
    cpf_bruto = (request.form.get("cpf") or "").strip()
    cpf = _cpf_normalizar(cpf_bruto) if cpf_bruto else None
    if cpf_bruto and not cpf:
        flash("CPF inválido. Confira os números.", "danger")
        return _redirect_admin("usuarios")
    if cpf and Usuario.query.filter_by(cpf=cpf).first():
        flash("Este CPF já está no cadastro de outra pessoa.", "danger")
        return _redirect_admin("usuarios")

    if enviar_convite:
        # Senha aleatória descartável: o colaborador define a própria pelo link.
        senha = secrets.token_urlsafe(32)
        exigir_troca = True
    else:
        senha = request.form.get("senha", "")
        problem = _validar_senha_admin(senha, request.form.get("confirmar_senha", ""))
        if problem:
            flash(problem, "danger")
            return _redirect_admin("usuarios")

    novo_usuario = Usuario(
        nome=nome,
        email=email,
        email_confirmado=True,
        tipo_contrato=tipo_contrato,
        departamento_id=departamento_id,
        cpf=cpf,
    )
    _aplicar_senha(novo_usuario, senha, exigir_troca)
    db.session.add(novo_usuario)
    db.session.commit()
    registrar_log(current_user.id, f"Cadastrou usuário {nome} ({email})", novo_usuario.id)

    if not enviar_convite:
        aviso = " Ele deverá trocar a senha no primeiro acesso." if exigir_troca else ""
        flash(f"Colaborador {nome} cadastrado com a senha definida.{aviso}", "success")
        return _redirect_admin("usuarios")

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
        flash(f"Colaborador {nome} cadastrado! E-mail de convite enviado.", "success")
    else:
        flash(
            f"Colaborador {nome} cadastrado, mas o convite não pôde ser enviado. "
            "Defina uma senha em Configurar > Alterar senha.",
            "warning",
        )
    return _redirect_admin("usuarios")


# Exceção temporária à separação de funções: contas (e-mails) que podem
# aprovar/recusar a PRÓPRIA solicitação de correção. Fica no ambiente do
# servidor (não na tela) para ninguém conseguir se incluir pelo sistema;
# cada uso vai para o log com a marca [AUTOAPROVAÇÃO].
AUTOAPROVACAO_EMAILS = set(_env_list("AUTOAPROVACAO_EMAILS"))


def _pode_autoaprovar(usuario):
    return bool(usuario.is_rh) and (usuario.email or "").lower() in AUTOAPROVACAO_EMAILS


def _pode_trocar_senha_de(autor, alvo):
    """TI troca a senha de qualquer conta; RH, de colaboradores e do RH,
    nunca de contas com papel TI. A própria senha é trocada pelo perfil."""
    if autor.id == alvo.id:
        return False
    if autor.is_ti:
        return True
    return bool(autor.is_rh) and not alvo.is_ti


@app.route("/admin/usuarios/<int:user_id>/senha", methods=["POST"])
@login_required
@gestao_required
def admin_alterar_senha_usuario(user_id):
    user = Usuario.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Para alterar a sua própria senha, use a opção do seu perfil.", "warning")
        return _redirect_admin("usuarios")
    if not _pode_trocar_senha_de(current_user, user):
        # Trocar a senha de uma conta da TI permitiria entrar nela e assumir
        # os acessos dela; só a própria TI faz isso.
        flash(f"{user.nome} tem papel de TI: só a TI pode trocar a senha dessa conta.", "danger")
        return _redirect_admin("usuarios")

    senha = request.form.get("nova_senha", "")
    problem = _validar_senha_admin(senha, request.form.get("confirmar_senha", ""))
    if problem:
        flash(problem, "danger")
        return _redirect_admin("usuarios")

    exigir_troca = request.form.get("exigir_troca") == "on"
    _aplicar_senha(user, senha, exigir_troca)
    db.session.commit()
    registrar_log(
        current_user.id,
        f"Alterou a senha do usuário {user.nome}" + (" (troca obrigatória no próximo acesso)" if exigir_troca else ""),
        user.id,
    )
    aviso = " A pessoa deverá trocar a senha no próximo acesso." if exigir_troca else ""
    flash(f"Senha de {user.nome} alterada. As sessões abertas dele foram encerradas.{aviso}", "success")
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
        _aplicar_senha(usuario, senha, exigir_troca=False)  # também anula links pendentes
        db.session.commit()
        registrar_log(usuario.id, "Definiu a senha pelo link de convite", usuario.id)
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
    if not app.config["ESQUECI_SENHA_ATIVO"]:
        flash(_MSG_SENHA_PELO_RH, "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]

        def tarefa():
            # Fora da requisição: o tempo de resposta não revela se o e-mail
            # existe (gerar token + chamar o Resend leva centenas de ms).
            with app.test_request_context(base_url=app.config["PUBLIC_BASE_URL"]):
                user = Usuario.query.filter(db.func.lower(Usuario.email) == email).first()
                if not user:
                    return
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
                registrar_log(None, f"Pediu redefinição de senha por e-mail: {user.nome}", user.id)

        if app.config.get("TESTING"):
            tarefa()
        else:
            threading.Thread(target=tarefa, name="esqueci-senha", daemon=True).start()
        # A resposta é a mesma para qualquer endereço, inclusive inexistente.
        flash("Se o e-mail estiver cadastrado, você receberá instruções para redefinir a senha.", "info")

    return render_template("forgot_password.html")


@app.route("/confirm_email/<token>", methods=["GET", "POST"])
def confirm_email(token):
    """Links de confirmação antigos do autocadastro não criam mais contas."""
    flash(_MSG_CADASTRO_FECHADO, "info")
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
        _aplicar_senha(usuario, senha, exigir_troca=False)  # também anula o convite pendente
        db.session.commit()
        registrar_log(usuario.id, f"Redefiniu a senha pelo e-mail (IP {request.remote_addr})", usuario.id)
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
    if current_user.is_rh:
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

    # Raio ativo e a pessoa não isenta: a página checa a posição e só libera
    # o botão dentro do raio (o servidor confere de novo ao bater).
    local_trabalho = None if current_user.ponto_fora_do_raio else config_local_trabalho()
    if local_trabalho:
        local_trabalho.update(tolerancia_m=GEO_TOLERANCIA_MAX_M, precisao_max_m=GEO_PRECISAO_MAX_M)

    return render_template(
        "index.html",
        local_trabalho=local_trabalho,
        exige_localizacao=local_trabalho is not None,
        ultimo_ponto=ultimo_ponto,
        data_hoje=data_hoje,
        total_solicitacoes_pendentes=total_solicitacoes_pendentes,
        pontos_today=lista_pontos_hoje,
        proximo_tipo=proximo_tipo,
        jornada=jornada_vigente(departamento_id=current_user.departamento_id),
        espelhos_pendentes=(EspelhoMensal.query.join(FechamentoMes)
                            .filter(EspelhoMensal.usuario_id == current_user.id,
                                    FechamentoMes.fechado.is_(True),
                                    EspelhoMensal.ciencia_status == "pendente")
                            .order_by(FechamentoMes.ano.desc(), FechamentoMes.mes.desc()).all()),
        afastamento_hoje=Afastamento.query.filter(
            Afastamento.usuario_id == current_user.id,
            Afastamento.data_inicio <= datetime.now(ZoneInfo("America/Sao_Paulo")).date(),
            Afastamento.data_fim >= datetime.now(ZoneInfo("America/Sao_Paulo")).date(),
        ).first(),
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
    local, erro_local = _checar_local_da_batida(request.form, current_user)
    if erro_local:
        flash(erro_local, "danger")
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
        foi_ajustado=False,
        **(local or {}),
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
    local, erro_local = _checar_local_da_batida(request.form, current_user)
    if erro_local:
        flash(erro_local, "danger")
        return redirect(url_for("index"))
    novo_ponto, erro = _registrar_proximo_ponto(current_user.id, local=local)
    if erro:
        flash(erro, "warning" if "recentemente" in erro else "danger")
        return redirect(url_for("index"))
    flash(f"Ponto ({novo_ponto.tipo}) registrado às {novo_ponto.hora} com sucesso!", "success")
    return redirect(url_for("index"))


# ---------- Raio do local de trabalho (batida pelo app) ----------
GEO_RAIO_MIN, GEO_RAIO_MAX = 30, 5000
GEO_TOLERANCIA_MAX_M = 100     # imprecisão do GPS descontada da distância, no máximo
GEO_PRECISAO_MAX_M = 1000      # acima disso a leitura não serve (ex.: localização só por IP)


def config_local_trabalho():
    """Local de trabalho configurado pela TI, ou None se o raio estiver desligado."""
    if _get_config("geo_ativo", "false") != "true":
        return None
    try:
        lat, lon = float(_get_config("geo_lat", "")), float(_get_config("geo_lon", ""))
        raio = int(_get_config("geo_raio_m", "200"))
    except ValueError:
        return None
    return {"lat": lat, "lon": lon, "raio_m": raio}


def _distancia_m(lat1, lon1, lat2, lon2):
    """Distância em metros entre dois pontos (fórmula de haversine)."""
    r = 6_371_000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _checar_local_da_batida(form, usuario=None):
    """Com o raio ativo, exige a localização do aparelho dentro dele
    (exceto para quem a TI liberou a bater de qualquer lugar).

    Devolve (dados_do_local | None, mensagem_de_erro | None). Obs.: a posição
    vem do navegador; impede o uso comum fora da empresa, mas não resiste a
    quem falsificar o GPS de propósito."""
    local = config_local_trabalho()
    if local is None or (usuario is not None and usuario.ponto_fora_do_raio):
        return None, None
    try:
        lat, lon = float(form.get("lat", "")), float(form.get("lon", ""))
        precisao = float(form.get("precisao", "") or 9999)
    except ValueError:
        return None, "Ative a localização do aparelho para bater o ponto."
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or not math.isfinite(precisao):
        return None, "Localização inválida. Tente de novo."
    if precisao > GEO_PRECISAO_MAX_M:
        return None, "Localização imprecisa demais. Ative o GPS (localização precisa) e tente de novo."
    distancia = _distancia_m(lat, lon, local["lat"], local["lon"])
    dados = {"latitude": lat, "longitude": lon, "precisao_m": round(precisao), "distancia_m": round(distancia)}
    if distancia - min(precisao, GEO_TOLERANCIA_MAX_M) > local["raio_m"]:
        return None, (f"Você está a {_formatar_distancia(distancia)} do local de trabalho "
                      f"(o limite é {_formatar_distancia(local['raio_m'])}). O ponto não foi registrado.")
    return dados, None


def _formatar_distancia(metros):
    return f"{metros / 1000:.1f} km".replace(".", ",") if metros >= 1000 else f"{round(metros)} m"


def _proximo_tipo_ponto(usuario_id, data_atual):
    """Entrada ou Saída, conforme as batidas do dia (nunca fica sem próximo)."""
    registros_hoje = RegistroPonto.query.filter_by(
        usuario_id=usuario_id, data=data_atual
    ).order_by(RegistroPonto.hora.asc()).all()
    faltantes = identificar_pontos_faltantes(registros_hoje)
    return faltantes[0] if faltantes else "Entrada"


def _registrar_proximo_ponto(usuario_id, foto_jpeg=None, local=None):
    """Registra o próximo ponto (Entrada/Saída) do usuário agora.

    Usado pelo botão do app e pelo quiosque (que manda a foto junto, gravada
    na mesma transação). Devolve (registro, None) ou (None, mensagem de erro).
    """
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    data_atual = agora.strftime("%d/%m/%Y")
    hora_atual = agora.strftime("%H:%M:%S")
    proximo = _proximo_tipo_ponto(usuario_id, data_atual)

    # Anti-duplicata: bloqueia QUALQUER ponto criado nos últimos 5s (duplo
    # clique, ou duas fotos seguidas no quiosque).
    try:
        ultimo = RegistroPonto.query.filter(
            RegistroPonto.usuario_id == usuario_id,
            RegistroPonto.data == data_atual,
        ).order_by(RegistroPonto.id.desc()).first()
        if ultimo:
            dup_h, dup_m, dup_s = (int(x) for x in ultimo.hora.split(":"))
            dup_dt = agora.replace(hour=dup_h, minute=dup_m, second=dup_s, microsecond=0)
            if dup_dt >= agora - timedelta(seconds=5):
                return None, "Ponto já registrado recentemente. Por favor, aguarde."
    except (ValueError, AttributeError):
        pass

    novo_ponto = RegistroPonto(data=data_atual, tipo=proximo, hora=hora_atual,
                               usuario_id=usuario_id, foi_ajustado=False, **(local or {}))
    if foto_jpeg is not None:
        novo_ponto.foto = FotoPonto(dados=foto_jpeg, mime="image/jpeg")
    db.session.add(novo_ponto)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Falha ao registrar ponto do usuário %s", usuario_id)
        return None, "Erro ao registrar ponto. Tente novamente."
    _invalidar_notif_cache(usuario_id)
    return novo_ponto, None

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

    # Apuração (usa todas as batidas, independente do filtro de tipo da tela).
    dias_apurados, totais = apurar_periodo(current_user, data_inicio_obj, data_fim_obj)
    apuracao_por_dia = {ap.data: ap for ap in dias_apurados}

    for d_obj in datas_intervalo:
        data_str = d_obj.strftime("%d/%m/%Y")
        registros_do_dia = dias_registrados.get(d_obj, [])
        registros_do_dia = sorted(
            registros_do_dia,
            key=lambda r: _parse_hora(getattr(r, "hora", None)) or datetime.min.time()
        )

        ap = apuracao_por_dia[d_obj]
        afast = ap.afastamento
        util = eh_dia_util(d_obj, current_user.departamento_id)
        # Se NÃO for dia útil e NÃO houver batidas, pula o dia
        if not util and not ap.batidas:
            continue

        if ap.extras:
            diferenca = "+" + fmt_hhmm(ap.extras) + (" (100%)" if ap.extra_100 and not ap.extra_50 else "")
        elif ap.atraso:
            diferenca = "-" + fmt_hhmm(ap.atraso)
        else:
            diferenca = None
        saldo = {
            "tem_registro": bool(ap.batidas),
            "total_trabalhado_fmt": f"{fmt_hhmm(ap.trabalhado)}h",
            "is_excedente": bool(ap.extras),
            "is_faltante": bool(ap.atraso),
            "diferenca_fmt": diferenca,
            "neutro": ("incompleto" if ap.incompleto else "na tolerância" if ap.tolerado
                       else "em aberto" if ap.em_aberto else "0min"),
        }
        incompleto = (ap.incompleto or ap.falta) and not afast

        historico_analisado.append({
            "data": data_str,
            "registros": registros_do_dia,
            "incompleto": incompleto,
            "saldo": saldo,
            "falta": ap.falta,
            "alertas": [a for a in ap.alertas if a != "Entrada sem saída"],
            "afastamento": AFASTAMENTO_TIPOS.get(afast) if afast else None,
        })

    return render_template(
        "meu_historico.html",
        historico=historico_analisado,
        totais=totais,
        fmt_hhmm=fmt_hhmm,
        is_pj=current_user.tipo_contrato == "PJ",
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

        hora = _hora_valida(hora)
        hora_original = _hora_valida(hora_original) if hora_original else None
        if tipo_ponto not in PONTOS_PERMITIDOS or not hora:
            flash("Tipo de ponto ou hora inválidos.", "danger")
            return redirect(url_for("solicitar_correcao"))

        try:
            data_obj = datetime.strptime(data_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Data inválida. Verifique o valor informado.", "danger")
            return redirect(url_for("solicitar_correcao"))

        if data_obj > hoje:
            flash("Data inválida. Não é permitido solicitar ajuste para datas futuras.", "danger")
            return redirect(url_for("solicitar_correcao"))

        primeiro_dia, fechamento, limite = janela_correcao(hoje)
        if hoje > limite:
            flash(
                f"O prazo para pedir correções deste mês terminou em {limite.strftime('%d/%m/%Y')} "
                f"(o mês fecha em {fechamento.strftime('%d/%m/%Y')}). Fale com o RH.",
                "danger",
            )
            return redirect(url_for("solicitar_correcao"))
        if data_obj < primeiro_dia:
            flash("Este período já foi fechado. Só é possível pedir correção de dias do mês atual; fale com o RH.", "danger")
            return redirect(url_for("solicitar_correcao"))
        if mes_fechado(data_obj):
            flash("Este mês já foi fechado pelo RH. Fale com o RH se precisar de algum ajuste.", "danger")
            return redirect(url_for("solicitar_correcao"))

        data_formatada = data_obj.strftime("%d/%m/%Y")

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

    primeiro_dia, fechamento, limite = janela_correcao(hoje)
    return render_template(
        "solicitar_correcao.html",
        solicitacoes=minhas_solicitacoes,
        data_hoje=hoje.strftime("%Y-%m-%d"),
        data_minima=primeiro_dia.strftime("%Y-%m-%d"),
        correcao_limite=limite,
        correcao_fechamento=fechamento,
        correcao_aberta=hoje <= limite,
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

    dias, tot = apurar_periodo(usuario, data_inicio_obj, data_fim_obj, hoje=hoje_real)

    max_pares = max([1] + [(len(x.batidas) + 1) // 2 for x in dias])
    cabecalho = ["Dia"]
    for n in range(1, max_pares + 1):
        cabecalho.append(f"Entrada {n}")
        cabecalho.append(f"Saída {n}")
    cabecalho.append("Trabalhado")
    if not is_pj:
        cabecalho += [f"Extras {tot['extra_util_pct']}%", f"Extras {tot['extra_descanso_pct']}%", "Atraso/Falta"]
    cabecalho.append("Situação")
    tabela_linhas = [cabecalho]

    vazio = lambda seg: fmt_hhmm(seg) if seg else ""
    for x in dias:
        # Dias de folga sem batida não aparecem na folha (como antes).
        if not x.batidas and x.tipo_dia in ("descanso", "domingo", "feriado") and not x.futuro:
            continue
        if not x.batidas and x.futuro and x.tipo_dia != "util":
            continue
        linha = [x.data.strftime("%d/%m/%Y")]
        for i, (tipo, hora) in enumerate(x.batidas):
            esperado = "Entrada" if i % 2 == 0 else "Saída"
            cel = (hora or "")[:5]
            if tipo != esperado:
                cel = f"E {cel}" if tipo == "Entrada" else f"S {cel}"
            linha.append(cel)
        while len(linha) < 1 + max_pares * 2:
            linha.append("")
        linha.append(f"{fmt_hhmm(x.trabalhado)}h" if x.batidas else "")
        if not is_pj:
            linha += [vazio(x.extra_50), vazio(x.extra_100), vazio(x.atraso + x.falta_seg)]
        linha.append(x.situacao)
        tabela_linhas.append(linha)

    total_extras = tot["extra_50"] + tot["extra_100"]
    total_faltantes = tot["atraso"] + tot["falta_seg"]
    hrs_t, mins_t = divmod(tot["trabalhado"] // 60, 60)
    hrs_e, mins_e = divmod(total_extras // 60, 60)
    hrs_f, mins_f = divmod(total_faltantes // 60, 60)

    return {
        "usuario": usuario,
        "is_pj": is_pj,
        "data_inicio_obj": data_inicio_obj,
        "data_fim_obj": data_fim_obj,
        "tabela_linhas": tabela_linhas,
        "max_pares": max_pares,
        "dias": dias,
        "totais": tot,
        "total_segundos_trabalhados": tot["trabalhado"],
        "total_segundos_extras": total_extras,
        "total_segundos_faltantes": total_faltantes,
        "total_faltas_dias": tot["faltas_dias"],
        "total_dias_afastados": tot["afastados_dias"],
        "hrs_t": hrs_t,
        "mins_t": mins_t,
        "hrs_e": hrs_e,
        "mins_e": mins_e,
        "hrs_f": hrs_f,
        "mins_f": mins_f,
    }


def _gerar_arquivo_folha_ponto(dados, formato):
    usuario = dados["usuario"]
    is_pj = dados["is_pj"]
    data_inicio_obj = dados["data_inicio_obj"]
    data_fim_obj = dados["data_fim_obj"]
    tabela_linhas = dados["tabela_linhas"]
    max_pares = dados["max_pares"]

    if formato == "pdf":
        from reportlab.lib.pagesizes import landscape
        tot = dados["totais"]
        buffer = io.BytesIO()
        pagina = landscape(letter)
        pdf = SimpleDocTemplate(buffer, pagesize=pagina, rightMargin=24, leftMargin=24, topMargin=24, bottomMargin=24)
        elementos = []
        estilos = getSampleStyleSheet()

        titulo_estilo = ParagraphStyle("T", parent=estilos["Heading1"], fontSize=16, alignment=1, spaceAfter=10)
        elementos.append(Paragraph(f"<b>Folha de Ponto - {_pdf_text(usuario.nome)}</b>", titulo_estilo))
        periodo_str = f"{data_inicio_obj.strftime('%d/%m/%Y')} a {data_fim_obj.strftime('%d/%m/%Y')}"
        elementos.append(
            Paragraph(
                f"<b>E-mail:</b> {_pdf_text(usuario.email)} | <b>Contrato:</b> {'PJ' if is_pj else 'CLT'} | <b>Período:</b> {periodo_str} | <b>Emissão:</b> {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y às %H:%M')}",
                estilos["Normal"]
            )
        )
        elementos.append(Spacer(1, 10))

        largura_util = pagina[0] - pdf.leftMargin - pdf.rightMargin
        fixas = [66, 56] + ([52, 52, 58] if not is_pj else []) + [130]
        col_batidas = max(1, max_pares * 2)
        larg_batida = max(34.0, (largura_util - sum(fixas)) / col_batidas)
        colWidths = [fixas[0]] + [larg_batida] * col_batidas + fixas[1:]
        tabela = Table(tabela_linhas, colWidths=colWidths, repeatRows=1)
        estilo_tabela = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ]
        for i, linha in enumerate(tabela_linhas[1:], start=1):
            situacao = linha[-1]
            if situacao in ("FALTA", "INCOMPLETO"):
                estilo_tabela += [("TEXTCOLOR", (0, i), (-1, i), colors.HexColor("#b91c1c")),
                                  ("FONTNAME", (0, i), (-1, i), "Helvetica-Bold"),
                                  ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fdecec"))]
            elif situacao.isupper() and situacao not in ("-",):
                estilo_tabela.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#eef4ff")))
            elif "acima" in situacao or "Intervalo" in situacao or "Sem intervalo" in situacao or "Interjornada" in situacao:
                estilo_tabela.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fff7e6")))

        tabela.setStyle(TableStyle(estilo_tabela))
        elementos.append(tabela)
        elementos.append(Spacer(1, 14))

        dados_resumo = [["Horas trabalhadas:", f"{fmt_hhmm(tot['trabalhado'])}h"]]
        if not is_pj:
            dados_resumo += [
                [f"Horas extras {tot['extra_util_pct']}% (dias úteis/folgas):", f"{fmt_hhmm(tot['extra_50'])}h"],
                [f"Horas extras {tot['extra_descanso_pct']}% (domingos/feriados):", f"{fmt_hhmm(tot['extra_100'])}h"],
                ["Atrasos / saídas antecipadas:", f"{fmt_hhmm(tot['atraso'])}h"],
                ["Faltas:", f"{tot['faltas_dias']} dia(s) ({fmt_hhmm(tot['falta_seg'])}h)"],
            ]
            if tot["noturno_ativo"]:
                dados_resumo.append([f"Adicional noturno {tot['noturno_pct']}% (hora reduzida):", f"{fmt_hhmm(tot['noturno_ficto'])}h"])
            if tot["incompletos"]:
                dados_resumo.append(["Dias incompletos (pendentes de correção):", f"{tot['incompletos']} dia(s)"])
            if tot["dias_acima_limite"]:
                dados_resumo.append(["Dias com extras acima do limite:", f"{tot['dias_acima_limite']} dia(s)"])
        if dados.get("total_dias_afastados"):
            dados_resumo.append(["Dias afastados (abonados):", f"{dados['total_dias_afastados']} dia(s)"])

        tabela_resumo = Table(dados_resumo, colWidths=[300, 200])
        tabela_resumo.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ]))
        elementos.append(tabela_resumo)
        elementos.append(Spacer(1, 8))
        elementos.append(Paragraph(
            "<font size=7 color='#555555'>Tolerância conforme CLT art. 58 §1º; extras pagas não compensam atrasos ou faltas.</font>",
            estilos["Normal"]))
        if dados.get("rodape"):
            elementos.append(Paragraph(f"<font size=7 color='#555555'>{_pdf_text(dados['rodape'])}</font>", estilos["Normal"]))

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


def _ler_carga_setor(form):
    """Lê carga (HH:MM) e dias do formulário de setor; devolve (carga, dias, erros)."""
    erros = []
    carga = _hhmm_para_min(form.get("carga_diaria"))
    if carga is None or not (60 <= carga <= 720):
        erros.append("Carga diária do setor: informe um valor entre 01:00 e 12:00.")
    dias = tuple(sorted({int(d) for d in form.getlist("dias_trabalho") if d.isdigit() and 0 <= int(d) <= 6}))
    if not dias:
        erros.append("Selecione pelo menos um dia de trabalho para o setor.")
    entrada, saida, erro_horario = _ler_horarios(form)
    if erro_horario:
        erros.append(erro_horario)
    return carga, dias, (entrada, saida), erros


def _salvar_versao_setor(dep, vigente_desde, carga, dias, horarios=(None, None)):
    versao = JornadaSetor.query.filter_by(departamento_id=dep.id, vigente_desde=vigente_desde).first()
    if versao is None:
        versao = JornadaSetor(departamento_id=dep.id, vigente_desde=vigente_desde)
        db.session.add(versao)
    versao.carga_diaria_min = carga
    versao.dias_trabalho = ",".join(map(str, dias))
    versao.horario_entrada_min, versao.horario_saida_min = horarios
    versao.alterado_por_nome = current_user.nome
    versao.alterado_em = datetime.now(ZoneInfo("America/Sao_Paulo"))


def _nome_setor_valido(nome, ignorar_id=None):
    if not nome:
        return "Informe o nome do setor."
    if len(nome) > 100:
        return "O nome do setor deve ter até 100 caracteres."
    q = Departamento.query.filter(db.func.lower(Departamento.nome) == nome.lower())
    if ignorar_id:
        q = q.filter(Departamento.id != ignorar_id)
    if q.first():
        return f"Já existe um setor chamado '{nome}'."
    return None


@app.route("/admin/departamentos", methods=["GET", "POST"])
@login_required
@ti_required
def gerenciar_departamentos():
    """Cria um setor, opcionalmente com carga horária própria."""
    if request.method == "GET":
        return _redirect_admin("parametros", "setores")

    nome = request.form.get("nome", "").strip()
    problema = _nome_setor_valido(nome)
    carga_propria = request.form.get("carga_propria") == "on"
    carga = dias = None
    horarios = (None, None)
    erros = [problema] if problema else []
    if carga_propria:
        carga, dias, horarios, erros_carga = _ler_carga_setor(request.form)
        erros += erros_carga
    if erros:
        for erro in erros:
            flash(erro, "danger")
        return _redirect_admin("parametros", "setores")

    dep = Departamento(nome=nome, descricao=request.form.get("descricao", "").strip() or None)
    db.session.add(dep)
    db.session.flush()
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    if carga_propria:
        _salvar_versao_setor(dep, hoje, carga, dias, horarios)
    db.session.commit()
    _limpar_cache_jornada()
    detalhe = (
        f" com carga de {_descrever_jornada_campo('carga_diaria_min', carga)} ({_descrever_jornada_campo('dias_trabalho', dias)})"
        if carga_propria else " usando a jornada padrão"
    )
    registrar_log(current_user.id, f"Criou o setor '{nome}'{detalhe}", dep.id)
    flash(f"Setor '{nome}' cadastrado{detalhe}.", "success")
    return _redirect_admin("parametros", "setores")


@app.route("/admin/departamentos/<int:id>/editar", methods=["POST"])
@login_required
@ti_required
def editar_departamento(id):
    """Renomeia o setor e/ou altera a carga horária a partir de uma data."""
    dep = Departamento.query.get_or_404(id)
    nome = request.form.get("nome", "").strip()
    erros = []
    problema = _nome_setor_valido(nome, ignorar_id=dep.id)
    if problema:
        erros.append(problema)
    carga_propria = request.form.get("carga_propria") == "on"
    carga = dias = None
    horarios = (None, None)
    if carga_propria:
        carga, dias, horarios, erros_carga = _ler_carga_setor(request.form)
        erros += erros_carga
    try:
        vigente_desde = datetime.strptime(request.form.get("vigente_desde", ""), "%Y-%m-%d").date()
    except ValueError:
        vigente_desde = None
        erros.append("Informe a partir de quando a nova carga vale.")
    if vigente_desde and carga_propria and fechado_no_intervalo(vigente_desde, date.max):
        erros.append("A vigência não pode começar dentro de um mês fechado: " + msg_mes_fechado(*fechado_no_intervalo(vigente_desde, date.max)))
    if erros:
        for erro in erros:
            flash(erro, "danger")
        return _redirect_admin("parametros", "setores")

    mudancas = []
    if nome != dep.nome:
        mudancas.append(f"nome: {dep.nome} -> {nome}")
        dep.nome = nome

    atual = jornada_vigente(vigente_desde, dep.id)
    tinha_propria = atual.setor is not None
    if carga_propria:
        versao_atual = next((v for v in dep.jornadas if v.vigente_desde <= vigente_desde), None)
        horarios_atuais = (versao_atual.horario_entrada_min, versao_atual.horario_saida_min) if versao_atual else (None, None)
        if not tinha_propria or (atual.carga_diaria_min, atual.dias_trabalho, horarios_atuais) != (carga, dias, tuple(horarios)):
            _salvar_versao_setor(dep, vigente_desde, carga, dias, horarios)
            antes = (
                f"{_descrever_jornada_campo('carga_diaria_min', atual.carga_diaria_min)} "
                f"({_descrever_jornada_campo('dias_trabalho', atual.dias_trabalho)})"
                if tinha_propria else "jornada padrão"
            )
            depois = f"{_descrever_jornada_campo('carga_diaria_min', carga)} ({_descrever_jornada_campo('dias_trabalho', dias)})"
            if horarios[0] is not None:
                depois += f", {_descrever_jornada_campo('horario_entrada_min', horarios[0])}–{_descrever_jornada_campo('horario_saida_min', horarios[1])}"
            mudancas.append(f"carga a partir de {vigente_desde.strftime('%d/%m/%Y')}: {antes} -> {depois}")
    elif tinha_propria:
        # Voltar para a jornada padrão a partir da data: remove versões dali em diante.
        removidas = JornadaSetor.query.filter(
            JornadaSetor.departamento_id == dep.id, JornadaSetor.vigente_desde >= vigente_desde
        ).delete(synchronize_session=False)
        restante = JornadaSetor.query.filter(
            JornadaSetor.departamento_id == dep.id, JornadaSetor.vigente_desde < vigente_desde
        ).count()
        if restante:
            # Há carga própria antes da data: a volta ao padrão precisa ser
            # desde a primeira versão, senão a anterior continuaria valendo.
            db.session.rollback()
            flash("Para voltar à jornada padrão, use a data da primeira carga do setor (ou uma anterior).", "danger")
            return _redirect_admin("parametros", "setores")
        if removidas:
            mudancas.append("passou a usar a jornada padrão")

    if not mudancas:
        flash("Nenhuma alteração no setor.", "info")
        return _redirect_admin("parametros", "setores")
    db.session.commit()
    _limpar_cache_jornada()
    _invalidar_notif_cache()
    registrar_log(current_user.id, f"Alterou o setor '{dep.nome}': " + "; ".join(mudancas), dep.id)
    if vigente_desde < datetime.now(ZoneInfo("America/Sao_Paulo")).date() and carga_propria:
        flash(f"Setor '{dep.nome}' atualizado com vigência retroativa: os cálculos desde {vigente_desde.strftime('%d/%m/%Y')} foram refeitos.", "warning")
    else:
        flash(f"Setor '{dep.nome}' atualizado.", "success")
    return _redirect_admin("parametros", "setores")


@app.route("/admin/departamentos/excluir/<int:id>", methods=["POST"])
@login_required
@ti_required
def excluir_departamento(id):
    dep = Departamento.query.get_or_404(id)
    membros = Usuario.query.filter_by(departamento_id=dep.id).count()
    if membros:
        flash(f"O setor '{dep.nome}' tem {membros} colaborador(es). Mova-os para outro setor antes de excluir.", "danger")
        return _redirect_admin("parametros", "setores")
    nome_dep = dep.nome
    JornadaSetor.query.filter_by(departamento_id=dep.id).delete(synchronize_session=False)
    db.session.delete(dep)
    db.session.commit()
    _limpar_cache_jornada()
    registrar_log(current_user.id, f"Excluiu o setor '{nome_dep}'", id)
    flash(f"Setor '{nome_dep}' excluído.", "success")
    return _redirect_admin("parametros", "setores")

@app.route("/admin/usuarios/<int:user_id>/atualizar", methods=["POST"])
@login_required
@rh_required
def atualizar_usuario_admin(user_id):
    """Atualização de cadastro pelo RH. Para incluir um campo novo: ler e
    validar abaixo e acrescentá-lo em ``_resumo_cadastro`` (o log de
    auditoria registra o antes -> depois de cada campo alterado)."""
    user = Usuario.query.get_or_404(user_id)
    antes = _resumo_cadastro(user)

    nome = request.form.get("nome", user.nome or "").strip()
    email = request.form.get("email", user.email or "").strip().lower()
    if not nome or len(nome) > 100:
        flash("Informe o nome (até 100 caracteres).", "danger")
        return _redirect_admin("usuarios")
    if len(email) > 100 or not _EMAIL_RE.match(email):
        flash("Informe um e-mail válido (até 100 caracteres).", "danger")
        return _redirect_admin("usuarios")

    email_mudou = email != (user.email or "").lower()
    if email_mudou:
        if user.is_ti and not current_user.is_ti:
            # O e-mail é o login; trocá-lo numa conta da TI abriria caminho
            # para assumir a conta (mesma regra da troca de senha).
            flash(f"{user.nome} tem papel de TI: só a TI pode alterar o e-mail dessa conta.", "danger")
            return _redirect_admin("usuarios")
        if Usuario.query.filter(db.func.lower(Usuario.email) == email, Usuario.id != user.id).first():
            flash(f"Já existe um usuário com o e-mail {email}.", "danger")
            return _redirect_admin("usuarios")

    cpf_bruto = request.form.get("cpf")
    if cpf_bruto is not None:  # campo presente no formulário (vazio = remover)
        cpf = _cpf_normalizar(cpf_bruto) if cpf_bruto.strip() else None
        if cpf_bruto.strip() and not cpf:
            flash("CPF inválido. Confira os números.", "danger")
            return _redirect_admin("usuarios")
        if cpf and Usuario.query.filter(Usuario.cpf == cpf, Usuario.id != user.id).first():
            flash("Este CPF já está no cadastro de outra pessoa.", "danger")
            return _redirect_admin("usuarios")
        user.cpf = cpf

    user.nome = nome
    user.email = email
    user.departamento_id = _departamento_do_form(request.form.get("departamento_id"))
    tipo_contrato = request.form.get("tipo_contrato", "").strip().upper()
    if tipo_contrato in ("CLT", "PJ"):
        user.tipo_contrato = tipo_contrato

    if email_mudou:
        # Links de convite/redefinição foram para o endereço antigo (que pode
        # estar errado e ser de outra pessoa): deixam de valer.
        SecurityToken.query.filter(
            SecurityToken.usuario_id == user.id,
            SecurityToken.purpose.in_([SecurityToken.PURPOSE_RESET, SecurityToken.PURPOSE_INVITE]),
            SecurityToken.usado_em.is_(None),
        ).update({"usado_em": _local_now()}, synchronize_session=False)

    depois = _resumo_cadastro(user)
    mudancas = [f"{campo}: {antes[campo]} -> {depois[campo]}" for campo in depois if antes[campo] != depois[campo]]
    if not mudancas:
        db.session.rollback()
        flash(f"Nenhuma alteração no cadastro de {user.nome}.", "info")
        return _redirect_admin("usuarios")

    db.session.commit()
    _invalidar_notif_cache(user.id)
    registrar_log(current_user.id, f"Atualizou o cadastro de {antes['nome']}: " + "; ".join(mudancas), user_id)
    aviso = " O link de convite pendente foi cancelado; defina uma senha se a pessoa ainda não tiver acesso." if email_mudou else ""
    flash(f"Cadastro de {user.nome} atualizado.{aviso}", "success")
    return _redirect_admin("usuarios")


def _resumo_cadastro(user):
    """Campos do cadastro, legíveis, para comparar antes/depois no log."""
    setor = db.session.get(Departamento, user.departamento_id) if user.departamento_id else None
    return {
        "nome": user.nome or "",
        "e-mail": (user.email or "").lower(),
        "CPF": _cpf_mascarado(user.cpf),  # mascarado: o log não guarda o CPF inteiro
        "setor": setor.nome if setor else "nenhum",
        "contrato": user.tipo_contrato or "CLT",
    }

# ==========================================
#          ROTAS DE ADMINISTRAÇÃO
# ==========================================
def build_admin_logs_recentes(limit=5):
    logs = []
    limite_logs = max(limit, 1)

    registros = (RegistroPonto.query.join(Usuario).options(db.contains_eager(RegistroPonto.usuario))
                 .order_by(RegistroPonto.id.desc()).limit(limite_logs * 10).all())
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

    solicitacoes = (SolicitacaoCorrecao.query.join(Usuario)
                    .order_by(SolicitacaoCorrecao.id.desc()).limit(limite_logs * 4).all())
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
    if "usuarios" not in context:
        # Modais do shell (exportar, ponto manual) listam os colaboradores.
        context["usuarios"] = Usuario.query.order_by(Usuario.nome.asc()).all()
    if "total_solicitacoes_pendentes" not in context:
        context["total_solicitacoes_pendentes"] = SolicitacaoCorrecao.query.filter_by(status="Pendente").count()
    if "conteudo_inicial" not in context:
        # Monta a aba pedida já no servidor (o painel inclusive): uma única
        # fonte de HTML por aba e nada de piscar o Painel após salvar.
        fragmento = admin_fragment(initial_view)
        if isinstance(fragmento, str):
            context["conteudo_inicial"] = Markup(fragmento)
    return render_template("admin.html", initial_view=initial_view, **context)

MESES_PT = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho",
            "agosto", "setembro", "outubro", "novembro", "dezembro"]


def _indicadores_painel(hoje=None):
    """Indicadores do painel: conformidade do mês (até ontem) e fluxo de 7 dias.

    Por colaborador e dia: "conforme" = batidas fechadas; "incompleto" = sobrou
    Entrada sem Saída; "falta" = dia de trabalho (CLT) sem batida, sem
    afastamento e a partir do cadastro da pessoa. Hoje fica de fora (em aberto).
    """
    hoje = hoje or datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    ontem = hoje - timedelta(days=1)
    inicio_mes = hoje.replace(day=1)

    batidas = defaultdict(lambda: defaultdict(list))
    for r in RegistroPonto.query.filter(RegistroPonto.data.like(f"%/{hoje.strftime('%m/%Y')}")).all():
        try:
            d = datetime.strptime(r.data, "%d/%m/%Y").date()
        except (TypeError, ValueError):
            continue
        if inicio_mes <= d <= ontem and r.tipo in PONTOS_PERMITIDOS:
            batidas[r.usuario_id][d].append((r.hora or "", r.tipo))

    conformes = incompletos = faltas = 0
    for u in Usuario.query.all():
        dias = batidas.get(u.id, {})
        for regs in dias.values():
            ultima = sorted(regs)[-1][1]
            if ultima == "Entrada":
                incompletos += 1
            else:
                conformes += 1
        if u.tipo_contrato == "PJ":
            continue
        d = max(inicio_mes, u.data_cadastro.date() if u.data_cadastro else inicio_mes)
        while d <= ontem:
            if d not in dias and eh_dia_util(d, u.departamento_id) and not afastamento_no_dia(u.id, d):
                faltas += 1
            d += timedelta(days=1)

    dias7 = [hoje - timedelta(days=i) for i in range(6, -1, -1)]
    chaves = [d.strftime("%d/%m/%Y") for d in dias7]
    por_dia = dict(
        db.session.query(RegistroPonto.data, db.func.count(db.distinct(RegistroPonto.usuario_id)))
        .filter(RegistroPonto.data.in_(chaves))
        .group_by(RegistroPonto.data)
        .all()
    )
    return {
        "conformes": conformes,
        "incompletos": incompletos,
        "faltas": faltas,
        "mes_referencia": MESES_PT[hoje.month - 1],
        "labels_semana": [f"{DIAS_SEMANA[d.weekday()][:3]} {d.strftime('%d/%m')}" for d in dias7],
        "dados_semana": [por_dia.get(c, 0) for c in chaves],
    }


# ----------------------------------------------------------------------------
# Painel em janelas (Gridstack): cada usuário de gestão monta o seu — posição,
# largura e altura de cada bloco numa grade de 12 colunas. O layout fica em
# Configuracao("painel:<id>") como "cod.x.y.w.h,..." (cabe nos 255 caracteres).
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class BlocoPainel:
    titulo: str
    icone: str
    papel: str      # None (toda a gestão) | "rh" | "ti"
    w: int          # largura padrão (colunas de 12)
    h: int          # altura padrão (linhas da grade)
    min_w: int
    min_h: int
    tipo: str       # "metrica" | "bloco"
    codigo: str     # 2 letras usadas no layout salvo


PAINEL_BLOCOS = {
    "colaboradores": BlocoPainel("Colaboradores", "bi-people-fill", None, 3, 2, 2, 2, "metrica", "co"),
    "conformes": BlocoPainel("Dias conformes", "bi-check-circle-fill", None, 3, 2, 2, 2, "metrica", "cf"),
    "pendencias": BlocoPainel("Incompletos / faltas", "bi-exclamation-triangle-fill", None, 3, 2, 2, 2, "metrica", "pe"),
    "solic_qtd": BlocoPainel("Solicitações pendentes", "bi-pencil-square", "rh", 3, 2, 2, 2, "metrica", "sq"),
    "atalhos": BlocoPainel("Ações rápidas", "bi-lightning-charge", None, 12, 2, 2, 2, "bloco", "at"),
    "presenca": BlocoPainel("Presença nos últimos 7 dias", "bi-bar-chart", None, 8, 5, 3, 3, "bloco", "pr"),
    "conformidade": BlocoPainel("Conformidade de pontos", "bi-pie-chart", None, 4, 5, 3, 3, "bloco", "cd"),
    "atividades": BlocoPainel("Atividades recentes", "bi-clock-history", None, 7, 7, 3, 3, "bloco", "av"),
    "feriados": BlocoPainel("Feriados do mês", "bi-calendar-check", None, 5, 7, 3, 3, "bloco", "fe"),
    "sem_entrada": BlocoPainel("Sem entrada hoje", "bi-person-exclamation", "rh", 4, 5, 3, 3, "bloco", "se"),
    "afastados": BlocoPainel("Afastados e próximos", "bi-calendar-x", "rh", 4, 5, 3, 3, "bloco", "af"),
    "alertas": BlocoPainel("Alertas CLT", "bi-shield-exclamation", None, 4, 5, 3, 3, "bloco", "al"),
    "solicitacoes": BlocoPainel("Solicitações para aprovar", "bi-inbox", "rh", 6, 5, 3, 3, "bloco", "so"),
    "extras": BlocoPainel("Horas extras do mês", "bi-graph-up-arrow", "rh", 6, 5, 3, 3, "bloco", "ex"),
}
PAINEL_POR_CODIGO = {b.codigo: bid for bid, b in PAINEL_BLOCOS.items()}
PAINEL_PADRAO = [
    "colaboradores", "conformes", "pendencias", "solic_qtd", "atalhos",
    "presenca", "conformidade", "atividades", "feriados",
    "sem_entrada", "afastados", "alertas", "solicitacoes", "extras",
]
PAINEL_COLUNAS = 12
PAINEL_MAX_H = 20
PAINEL_MAX_Y = 300


def _painel_permitido(usuario, bloco_id):
    bloco = PAINEL_BLOCOS.get(bloco_id)
    if not bloco:
        return False
    return bloco.papel is None or (bloco.papel == "rh" and usuario.is_rh) or (bloco.papel == "ti" and usuario.is_ti)


def _painel_layout_padrao(usuario):
    """Empilha os blocos padrão em linhas, da esquerda para a direita."""
    layout, x, y, altura_linha = [], 0, 0, 0
    for bid in PAINEL_PADRAO:
        if not _painel_permitido(usuario, bid):
            continue
        b = PAINEL_BLOCOS[bid]
        # Sem o 4º cartão de RH, os 3 indicadores ocupam a linha inteira.
        w = 4 if (b.tipo == "metrica" and not usuario.is_rh) else b.w
        if x + w > PAINEL_COLUNAS:
            x, y, altura_linha = 0, y + altura_linha, 0
        layout.append({"id": bid, "x": x, "y": y, "w": w, "h": b.h})
        x += w
        altura_linha = max(altura_linha, b.h)
    return layout


def _int_ou(valor, padrao):
    try:
        return int(valor)
    except (TypeError, ValueError):
        return padrao


def _painel_normalizar(itens, usuario):
    """Valida [{id, x, y, w, h}]: só blocos permitidos, sem repetir, dentro da grade.

    Bloco sem posição (recém-adicionado) vai para baixo de tudo, com o tamanho padrão.
    """
    vistos, layout = set(), []
    for item in itens:
        bid = item.get("id")
        if not isinstance(bid, str) or bid in vistos or not _painel_permitido(usuario, bid):
            continue
        b = PAINEL_BLOCOS[bid]
        w = max(b.min_w, min(PAINEL_COLUNAS, _int_ou(item.get("w"), b.w)))
        h = max(b.min_h, min(PAINEL_MAX_H, _int_ou(item.get("h"), b.h)))
        x = _int_ou(item.get("x"), None)
        y = _int_ou(item.get("y"), None)
        if x is None or y is None:
            x, y = 0, max((i["y"] + i["h"] for i in layout), default=0)
        x = max(0, min(PAINEL_COLUNAS - w, x))
        y = max(0, min(PAINEL_MAX_Y, y))
        vistos.add(bid)
        layout.append({"id": bid, "x": x, "y": y, "w": w, "h": h})
    return layout


def _painel_layout(usuario):
    cfg = db.session.get(Configuracao, f"painel:{usuario.id}")
    if not cfg:
        return _painel_layout_padrao(usuario)
    itens = []
    for parte in cfg.valor.split(","):
        campos = parte.split(".")
        if len(campos) == 5 and campos[0] in PAINEL_POR_CODIGO:
            itens.append(dict(zip(("id", "x", "y", "w", "h"), [PAINEL_POR_CODIGO[campos[0]], *campos[1:]])))
    if not itens and cfg.valor:
        # Formato antigo ou corrompido: volta ao padrão em vez de mostrar vazio.
        return _painel_layout_padrao(usuario)
    return _painel_normalizar(itens, usuario)


def _painel_salvar_layout(usuario, layout):
    chave = f"painel:{usuario.id}"
    cfg = db.session.get(Configuracao, chave)
    if layout is None:
        if cfg:
            db.session.delete(cfg)
    else:
        valor = ",".join(f"{PAINEL_BLOCOS[i['id']].codigo}.{i['x']}.{i['y']}.{i['w']}.{i['h']}" for i in layout)
        if cfg:
            cfg.valor = valor
        else:
            db.session.add(Configuracao(chave=chave, valor=valor))
    db.session.commit()


def _painel_sem_entrada(hoje, agora_min):
    """Colaboradores CLT em dia de trabalho, sem afastamento e sem batida hoje."""
    com_batida = {uid for (uid,) in db.session.query(RegistroPonto.usuario_id)
                  .filter(RegistroPonto.data == hoje.strftime("%d/%m/%Y")).distinct()}
    lista = []
    for u in Usuario.query.order_by(Usuario.nome.asc()).all():
        if u.tipo_contrato == "PJ" or u.id in com_batida:
            continue
        if not eh_dia_util(hoje, u.departamento_id) or afastamento_no_dia(u.id, hoje):
            continue
        j = jornada_vigente(hoje, u.departamento_id)
        entrada = j.horario_entrada_min
        atrasado = entrada is not None and agora_min > entrada + j.tolerancia_marcacao_min
        lista.append({
            "nome": u.nome,
            "entrada": f"{entrada // 60:02d}:{entrada % 60:02d}" if entrada is not None else None,
            "atrasado": atrasado,
        })
    lista.sort(key=lambda x: (not x["atrasado"], x["nome"]))
    return lista


def _painel_afastados(hoje, dias=14):
    ate = hoje + timedelta(days=dias)
    itens = (Afastamento.query.options(db.joinedload(Afastamento.usuario))
             .filter(Afastamento.data_fim >= hoje, Afastamento.data_inicio <= ate)
             .order_by(Afastamento.data_inicio.asc()).all())
    return [{
        "nome": a.usuario.nome if a.usuario else "?",
        "tipo": a.tipo,
        "rotulo": a.rotulo,
        "inicio": a.data_inicio,
        "fim": a.data_fim,
        "em_curso": a.data_inicio <= hoje,
    } for a in itens]


def _painel_alertas_clt(usuarios):
    alertas = []
    for u in usuarios:
        regs = RegistroPonto.query.filter_by(usuario_id=u.id).order_by(RegistroPonto.id.desc()).limit(10).all()
        dias_agrupados = defaultdict(dict)
        for r in regs:
            dias_agrupados[r.data][r.tipo] = r.hora
        dias_ordenados = sorted(dias_agrupados.keys(), key=lambda d: datetime.strptime(d, "%d/%m/%Y"), reverse=True)
        for i in range(len(dias_ordenados) - 1):
            d_atual, d_anterior = dias_ordenados[i], dias_ordenados[i + 1]
            saida_ant = dias_agrupados[d_anterior].get("Saída")
            entrada_atual = dias_agrupados[d_atual].get("Entrada")
            if saida_ant and entrada_atual and not verificar_conformidade_clt(d_anterior, saida_ant, d_atual, entrada_atual):
                alertas.append({"nome": u.nome, "msg": f"Interjornada < 11h em {d_atual}"})
                break
    return alertas


def _painel_extras(usuarios, hoje):
    inicio = hoje.replace(day=1)
    linhas = []
    for u in usuarios:
        if u.tipo_contrato == "PJ":
            continue
        _, tot = apurar_periodo(u, inicio, hoje, hoje=hoje)
        if tot["extra_50"] or tot["extra_100"]:
            linhas.append({
                "nome": u.nome,
                "extra_50": tot["extra_50"],
                "extra_100": tot["extra_100"],
                "total": tot["extra_50"] + tot["extra_100"],
            })
    linhas.sort(key=lambda x: -x["total"])
    j = jornada_vigente(hoje)
    return {
        "linhas": linhas,
        "pct_util": j.extra_util_pct,
        "pct_descanso": j.extra_descanso_pct,
        "total_50": sum(x["extra_50"] for x in linhas),
        "total_100": sum(x["extra_100"] for x in linhas),
    }


def _contexto_painel(usuario):
    """Monta o painel calculando só o que os blocos visíveis usam."""
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    hoje = agora.date()
    layout = _painel_layout(usuario)
    ids = {i["id"] for i in layout}
    ctx = {
        "blocos": [dict(i, bloco=PAINEL_BLOCOS[i["id"]]) for i in layout],
        "catalogo": [{"id": bid, "titulo": b.titulo, "icone": b.icone} for bid, b in PAINEL_BLOCOS.items()
                     if _painel_permitido(usuario, bid)],
        "data_hoje": hoje,
        "mes_referencia": MESES_PT[hoje.month - 1],
        "fmt_hhmm": fmt_hhmm,
    }
    usuarios = Usuario.query.all() if ids & {"colaboradores", "alertas", "extras"} else []
    ctx["usuarios"] = usuarios
    if ids & {"conformes", "pendencias", "presenca", "conformidade"}:
        ctx.update(_indicadores_painel(hoje))
    if ids & {"solic_qtd", "solicitacoes"}:
        pend = (SolicitacaoCorrecao.query.options(db.joinedload(SolicitacaoCorrecao.usuario))
                .filter_by(status="Pendente").order_by(SolicitacaoCorrecao.id.asc()).all())
        ctx["solicitacoes_pendentes"] = pend
        ctx["total_solicitacoes_pendentes"] = len(pend)
    if "atividades" in ids:
        ctx["logs_recentes"] = build_admin_logs_recentes()
    if "feriados" in ids:
        _sincronizar_feriados_lib()
        ctx["feriados"] = _feriados_do_mes(hoje)
        ctx["regiao_uf"], ctx["regiao_cidade"], ctx["regiao_fonte"] = _regiao_display()
        ctx["ufs_brasil"] = UFS_BRASIL
    if "alertas" in ids:
        ctx["alertas_clt"] = _painel_alertas_clt(usuarios)
    if "sem_entrada" in ids:
        ctx["sem_entrada"] = _painel_sem_entrada(hoje, agora.hour * 60 + agora.minute)
    if "afastados" in ids:
        ctx["afastados"] = _painel_afastados(hoje)
    if "extras" in ids:
        ctx["extras"] = _painel_extras(usuarios, hoje)
    return ctx


@app.route("/admin/painel/layout", methods=["POST"])
@login_required
@gestao_required
def salvar_layout_painel():
    dados = request.get_json(silent=True) or {}
    if dados.get("restaurar"):
        _painel_salvar_layout(current_user, None)
        return jsonify({"ok": True})
    blocos = dados.get("blocos")
    if not isinstance(blocos, list) or len(blocos) > len(PAINEL_BLOCOS) * 2:
        return jsonify({"ok": False, "erro": "Layout inválido."}), 400
    layout = _painel_normalizar([b for b in blocos if isinstance(b, dict)], current_user)
    _painel_salvar_layout(current_user, layout)
    return jsonify({"ok": True, "blocos": layout})


@app.route("/admin")
@login_required
@gestao_required
def admin_panel():
    return render_admin_shell(initial_view="painel")

@app.route("/admin/fragment/<string:view_name>")
@login_required
@gestao_required
def admin_fragment(view_name):
    papel = _PAPEL_POR_ABA.get(view_name)
    if papel == "rh" and not current_user.is_rh or papel == "ti" and not current_user.is_ti:
        abort(403)
    if view_name == "painel":
        return render_template("admin_fragment_painel.html", **_contexto_painel(current_user))

    if view_name == "usuarios":
        usuarios = Usuario.query.order_by(Usuario.nome.asc()).all()
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
            d_inicio = _data_iso(data_inicio)
            d_fim = _data_iso(data_fim)

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

    if view_name == "parametros":
        return render_template("admin_fragment_parametros.html", **_contexto_parametros())

    if view_name == "afastamentos":
        return render_template("admin_fragment_afastamentos.html", **_contexto_afastamentos())

    if view_name == "fechamento":
        return render_template("admin_fragment_fechamento.html", **_contexto_fechamento(request.args.get("mes")))

    if view_name == "logs":
        return render_template("admin_fragment_logs.html", **_contexto_logs(request.args))

    return _redirect_admin("painel")

@app.route("/admin/historico")
@login_required
@rh_required
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
        d_inicio = _data_iso(data_inicio)
        d_fim = _data_iso(data_fim)

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
@rh_required
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
@rh_required
def responder_solicitacao(id, acao):
    solicitacao = SolicitacaoCorrecao.query.get_or_404(id)
    if acao not in {"aprovar", "recusar"}:
        abort(404)
    voltar = "painel" if request.form.get("voltar") == "painel" else "solicitacoes"
    autoaprovacao = False
    if solicitacao.usuario_id == current_user.id:
        if not _pode_autoaprovar(current_user):
            flash("Você não pode responder à sua própria solicitação. Outra pessoa do RH precisa analisá-la.", "danger")
            return _redirect_admin(voltar)
        autoaprovacao = True
    if solicitacao.status != "Pendente":
        # Reenvio (duplo clique, aba antiga) não pode duplicar batidas nem
        # inverter uma decisão já tomada.
        flash(f"Esta solicitação já foi respondida ({solicitacao.status}).", "warning")
        return _redirect_admin(voltar)

    if acao == "aprovar":
        try:
            data_sol = datetime.strptime(solicitacao.data_ponto, "%d/%m/%Y").date()
        except (TypeError, ValueError):
            data_sol = None
        if data_sol and mes_fechado(data_sol):
            flash(msg_mes_fechado(data_sol.year, data_sol.month) + " (a correção pode ser recusada).", "danger")
            return _redirect_admin("solicitacoes")
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

        if autoaprovacao:
            descricao_acao = "[AUTOAPROVAÇÃO] " + descricao_acao
        registrar_log(current_user.id, descricao_acao, id)
        flash("Solicitação APROVADA e registro atualizado!", "success")

    elif acao == "recusar":
        solicitacao.status = "Recusada"
        registrar_log(current_user.id, ("[AUTOAPROVAÇÃO] " if autoaprovacao else "")
                      + f"Recusou ajuste de {solicitacao.usuario.nome}: {solicitacao.tipo_ponto} em {solicitacao.data_ponto}", id)
        flash("Solicitação RECUSADA.", "warning")

    db.session.commit()
    _invalidar_notif_cache(solicitacao.usuario_id)
    return _redirect_admin(voltar)

@app.route("/admin/usuarios")
@login_required
@gestao_required
def admin_usuarios():

    usuarios = Usuario.query.order_by(Usuario.nome.asc()).all()
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

@app.route("/admin/usuarios/<int:user_id>/papeis", methods=["POST"])
@login_required
@ti_required
def atualizar_papeis_usuario(user_id):
    user = Usuario.query.get_or_404(user_id)
    novo_rh = request.form.get("is_rh") == "on"
    novo_ti = request.form.get("is_ti") == "on"
    novo_fora = request.form.get("ponto_fora_do_raio") == "on"

    if user.id == current_user.id and ((novo_rh and not user.is_rh) or (novo_ti and not user.is_ti)
                                       or (novo_fora and not user.ponto_fora_do_raio)):
        # Separação de funções: ninguém acumula papel ou isenção por conta própria.
        flash("Você não pode atribuir a si mesmo um papel novo ou a isenção do raio. Peça a outra pessoa da TI.", "danger")
        return _redirect_admin("usuarios")

    if user.is_ti and not novo_ti and Usuario.query.filter(Usuario.is_ti.is_(True), Usuario.id != user.id).count() == 0:
        flash("É preciso manter pelo menos uma pessoa com o papel TI.", "danger")
        return _redirect_admin("usuarios")

    papeis_mudaram = (novo_rh, novo_ti) != (bool(user.is_rh), bool(user.is_ti))
    isencao_mudou = novo_fora != bool(user.ponto_fora_do_raio)
    if not papeis_mudaram and not isencao_mudou:
        flash(f"Nenhuma alteração nos acessos de {user.nome}.", "info")
        return _redirect_admin("usuarios")

    if isencao_mudou:
        user.ponto_fora_do_raio = novo_fora
        db.session.commit()
        registrar_log(current_user.id, f"{'Liberou' if novo_fora else 'Retirou'} a batida de ponto fora do raio para {user.nome}", user_id)
        if not papeis_mudaram:
            flash(f"{user.nome} {'pode' if novo_fora else 'não pode mais'} bater o ponto fora do raio do local de trabalho.", "success")
            return _redirect_admin("usuarios")

    antes = user.papeis_texto
    user.is_rh, user.is_ti = novo_rh, novo_ti
    # Encerra as sessões para o novo conjunto de acessos valer imediatamente.
    user.auth_version = int(user.auth_version or 0) + 1
    db.session.commit()
    registrar_log(current_user.id, f"Alterou papéis de {user.nome}: {antes} -> {user.papeis_texto}", user_id)
    if user.id == current_user.id:
        flash("Seus papéis foram alterados. Entre novamente.", "info")
        logout_user()
        session.clear()
        return redirect(url_for("login"))
    flash(f"Papéis de {user.nome} atualizados para {user.papeis_texto}.", "success")
    return _redirect_admin("usuarios")

def registrar_log(usuario_id, acao, entidade_id=None):
    autor = None
    if usuario_id:
        if has_request_context() and current_user.is_authenticated and current_user.id == usuario_id:
            autor = current_user  # evita um SELECT extra no caso comum
        else:
            autor = db.session.get(Usuario, usuario_id)
    log = LogAuditoria(
        usuario_id=usuario_id,
        usuario_nome=autor.nome if autor else None,
        acao=acao[:200],  # coluna VARCHAR(200): o Postgres recusaria o excesso
        entidade_id=entidade_id,
    )
    db.session.add(log)
    db.session.commit()

@app.route("/admin/excluir-usuario/<int:user_id>", methods=["POST"])
@login_required
@rh_required
def excluir_usuario(user_id):
    user = Usuario.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash("Você não pode excluir sua própria conta.", "danger")
    elif user.tem_gestao:
        # Contas de RH/TI só saem depois que a TI remove os papéis (o que
        # também preserva a regra de manter ao menos uma pessoa na TI).
        flash(f"{user.nome} tem papel de RH/TI. A TI precisa remover os papéis antes da exclusão.", "danger")
    else:
        # Não excluímos logs de auditoria para manter conformidade (Portaria 671)
        # Excluímos apenas registros de ponto e solicitações associadas
        user_nome = user.nome
        try:
            # Preserva os logs de auditoria do usuário: guarda o nome e solta
            # o vínculo explicitamente (a FK também faz SET NULL; isto não
            # depende de a migração do init-db já ter rodado).
            LogAuditoria.query.filter(
                LogAuditoria.usuario_id == user.id,
                LogAuditoria.usuario_nome.is_(None),
            ).update({"usuario_nome": user_nome}, synchronize_session=False)
            LogAuditoria.query.filter_by(usuario_id=user.id).update(
                {"usuario_id": None}, synchronize_session=False
            )
            RegistroPonto.query.filter_by(usuario_id=user.id).delete()
            SolicitacaoCorrecao.query.filter_by(usuario_id=user.id).delete()
            Notificacao.query.filter_by(usuario_id=user.id).delete()
            SecurityToken.query.filter_by(usuario_id=user.id).delete()
            PushInscricao.query.filter_by(usuario_id=user.id).delete()
            LembreteEnviado.query.filter_by(usuario_id=user.id).delete()
            Afastamento.query.filter_by(usuario_id=user.id).delete()
            EspelhoMensal.query.filter_by(usuario_id=user.id).delete()
            RostoCadastrado.query.filter_by(usuario_id=user.id).delete()  # biometria sai junto
            db.session.expire(user)

            db.session.delete(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Falha ao excluir usuário %s", user_id)
            flash("Erro ao excluir usuário. Tente novamente.", "danger")
            return _redirect_admin("usuarios")

        _invalidar_notif_cache(user_id)
        registrar_log(current_user.id, f"Excluiu usuário {user_nome}", user_id)

        flash(f"Usuário {user_nome} excluído com sucesso!", "success")

    return _redirect_admin("usuarios")

# ==========================================
#     PARÂMETROS DE JORNADA (área da TI)
# ==========================================
def _hhmm_para_min(valor):
    try:
        h, m = (valor or "").strip().split(":")[:2]
        h, m = int(h), int(m)
        if 0 <= h <= 24 and 0 <= m < 60:
            return h * 60 + m
    except (ValueError, AttributeError):
        pass
    return None


def _min_para_hhmm(minutos):
    h, m = divmod(int(minutos), 60)
    return f"{h:02d}:{m:02d}"


def _descrever_jornada_campo(campo, valor):
    if campo in ("carga_diaria_min", "interjornada_min"):
        h, m = divmod(int(valor), 60)
        return f"{h}h{m:02d}" if m else f"{h}h"
    if campo == "dias_trabalho":
        return ", ".join(DIAS_SEMANA[d][:3] for d in sorted(valor)) or "nenhum"
    if campo == "noturno_ativo":
        return "ligado" if valor else "desligado"
    if campo in ("horario_entrada_min", "horario_saida_min"):
        return "sem horário" if valor is None else f"{int(valor) // 60:02d}:{int(valor) % 60:02d}"
    if campo.endswith("_pct"):
        return f"{valor}%"
    return f"{valor} min"


_JORNADA_ROTULOS = dict((c, r) for c, r, _mn, _mx in JORNADA_LIMITES)
_JORNADA_ROTULOS.update({
    "dias_trabalho": "Dias de trabalho",
    "noturno_ativo": "Adicional noturno (cálculo)",
    "horario_entrada_min": "Horário de entrada",
    "horario_saida_min": "Horário de saída",
})


def _contexto_parametros(form=None, erros=None):
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    atual = jornada_vigente(hoje)
    proximas = [v for v in _versoes_jornada() if v.vigente_desde > hoje]
    return {
        "jornada": atual,
        "jornada_proximas": sorted(proximas, key=lambda v: v.vigente_desde),
        "historico_jornada": ParametroJornada.query.order_by(ParametroJornada.vigente_desde.desc()).all(),
        "dias_semana": DIAS_SEMANA,
        "limites": {c: (mn, mx) for c, _r, mn, mx in JORNADA_LIMITES},
        "hoje_iso": hoje.isoformat(),
        "min_para_hhmm": _min_para_hhmm,
        "setores": _resumo_setores(hoje),
        "correcao_dias": correcao_dias_antes_fechamento(),
        "lembretes": config_lembretes(),
        "lembretes_cfg_bruto": {
            "a1": _get_config("lembrete_antecedencia_1", "10"),
            "a2": _get_config("lembrete_antecedencia_2", "5"),
        },
        "push_ativo": VAPID is not None,
        "correcao_janela": janela_correcao(hoje),
        "quiosque": QuiosqueDispositivo.query.first(),
        "quiosque_metodo": _quiosque_metodo(),
        "local_trabalho": {
            "ativo": _get_config("geo_ativo", "false") == "true",
            "lat": _get_config("geo_lat", ""),
            "lon": _get_config("geo_lon", ""),
            "raio_m": _get_config("geo_raio_m", "200"),
        },
        "geo_raio_limites": (GEO_RAIO_MIN, GEO_RAIO_MAX),
    }


def _resumo_setores(hoje):
    contagem = dict(
        db.session.query(Usuario.departamento_id, db.func.count(Usuario.id))
        .filter(Usuario.departamento_id.isnot(None))
        .group_by(Usuario.departamento_id)
        .all()
    )
    resumo = []
    for dep in Departamento.query.order_by(Departamento.nome.asc()).all():
        j = jornada_vigente(hoje, dep.id)
        proximas = [v for v in dep.jornadas if v.vigente_desde > hoje]
        resumo.append({
            "dep": dep,
            "jornada": j,
            "propria": j.setor is not None,
            "membros": contagem.get(dep.id, 0),
            "proxima": min(proximas, key=lambda v: v.vigente_desde) if proximas else None,
        })
    return resumo


CORRECAO_DIAS_ANTES_PADRAO = 1


def correcao_dias_antes_fechamento():
    try:
        return max(0, min(15, int(_get_config("correcao_dias_antes_fechamento", CORRECAO_DIAS_ANTES_PADRAO))))
    except (TypeError, ValueError):
        return CORRECAO_DIAS_ANTES_PADRAO


def janela_correcao(hoje=None):
    """Período em que o colaborador pode pedir correção de ponto.

    O mês fecha no último dia; os pedidos valem para datas do mês corrente
    e podem ser feitos até N dias antes do fechamento (parâmetro da TI).
    Devolve (primeiro_dia, fechamento, ultimo_dia_para_pedir).
    """
    hoje = hoje or datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    primeiro = hoje.replace(day=1)
    fechamento = (primeiro + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    limite = fechamento - timedelta(days=correcao_dias_antes_fechamento())
    return primeiro, fechamento, limite


def _ler_horarios(form):
    """Horário de entrada/saída (HH:MM), opcional: ambos ou nenhum."""
    bruto_e = (form.get("horario_entrada") or "").strip()
    bruto_s = (form.get("horario_saida") or "").strip()
    if not bruto_e and not bruto_s:
        return None, None, None
    entrada, saida = _hhmm_para_min(bruto_e), _hhmm_para_min(bruto_s)
    if entrada is None or saida is None:
        return None, None, "Informe os dois horários (entrada e saída) ou deixe ambos em branco."
    if saida <= entrada:
        return None, None, "O horário de saída precisa ser depois do horário de entrada."
    return entrada, saida, None


def _ler_jornada_do_form(form):
    """Valida o formulário; devolve (vigente_desde, valores, erros)."""
    erros = []
    try:
        vigente_desde = datetime.strptime(form.get("vigente_desde", ""), "%Y-%m-%d").date()
    except ValueError:
        vigente_desde = None
        erros.append("Informe a data a partir da qual as regras valem.")

    valores = {
        "carga_diaria_min": _hhmm_para_min(form.get("carga_diaria")),
        "interjornada_min": _hhmm_para_min(form.get("interjornada")),
    }
    for campo in ("tolerancia_marcacao_min", "tolerancia_diaria_min", "intervalo_minimo_min",
                  "limite_extras_dia_min", "extra_util_pct", "extra_descanso_pct", "noturno_pct"):
        try:
            valores[campo] = int(form.get(campo, ""))
        except ValueError:
            valores[campo] = None

    for campo, rotulo, minimo, maximo in JORNADA_LIMITES:
        valor = valores.get(campo)
        if valor is None or not (minimo <= valor <= maximo):
            if campo in ("carga_diaria_min", "interjornada_min"):
                faixa = f"entre {_min_para_hhmm(minimo)} e {_min_para_hhmm(maximo)}"
            elif campo.endswith("_pct"):
                faixa = f"entre {minimo}% e {maximo}%"
            else:
                faixa = f"entre {minimo} e {maximo} minutos"
            erros.append(f"{rotulo}: informe um valor {faixa}.")

    if valores.get("tolerancia_diaria_min") is not None and valores.get("tolerancia_marcacao_min") is not None \
            and valores["tolerancia_diaria_min"] < valores["tolerancia_marcacao_min"]:
        erros.append("A tolerância diária não pode ser menor que a tolerância por marcação.")

    dias = sorted({int(d) for d in form.getlist("dias_trabalho") if d.isdigit() and 0 <= int(d) <= 6})
    if not dias:
        erros.append("Selecione pelo menos um dia de trabalho.")
    valores["dias_trabalho"] = tuple(dias)
    valores["noturno_ativo"] = form.get("noturno_ativo") == "on"
    entrada, saida, erro_horario = _ler_horarios(form)
    if erro_horario:
        erros.append(erro_horario)
    valores["horario_entrada_min"], valores["horario_saida_min"] = entrada, saida
    return vigente_desde, valores, erros


@app.route("/admin/parametros/correcao", methods=["POST"])
@login_required
@ti_required
def admin_parametros_correcao():
    try:
        dias = int(request.form.get("correcao_dias_antes_fechamento", ""))
    except ValueError:
        dias = -1
    if not 0 <= dias <= 15:
        flash("Prazo de correção: informe de 0 a 15 dias antes do fechamento.", "danger")
        return _redirect_admin("parametros", "correcoes")
    anterior = correcao_dias_antes_fechamento()
    if dias == anterior:
        flash("Nenhuma regra foi alterada.", "info")
        return _redirect_admin("parametros", "correcoes")
    _set_config("correcao_dias_antes_fechamento", str(dias))
    db.session.commit()
    registrar_log(current_user.id, f"Alterou o prazo de correção: até {anterior} -> até {dias} dia(s) antes do fechamento do mês")
    flash(f"Prazo salvo: correções até {dias} dia(s) antes do fechamento do mês.", "success")
    return _redirect_admin("parametros", "correcoes")


@app.route("/admin/parametros", methods=["GET", "POST"])
@login_required
@ti_required
def admin_parametros():
    if request.method == "GET":
        return render_admin_shell(initial_view="parametros")

    vigente_desde, valores, erros = _ler_jornada_do_form(request.form)
    if not erros and vigente_desde and fechado_no_intervalo(vigente_desde, date.max):
        erros.append("A vigência não pode começar dentro de um mês fechado: " + msg_mes_fechado(*fechado_no_intervalo(vigente_desde, date.max)))
    if erros:
        for erro in erros:
            flash(erro, "danger")
        return _redirect_admin("parametros")

    anterior = jornada_vigente(vigente_desde)
    mudancas = [
        f"{_JORNADA_ROTULOS[c]}: {_descrever_jornada_campo(c, getattr(anterior, c))} -> {_descrever_jornada_campo(c, v)}"
        for c, v in valores.items()
        if getattr(anterior, c) != v
    ]
    if not mudancas:
        flash("Nenhuma regra foi alterada.", "info")
        return _redirect_admin("parametros")

    versao = ParametroJornada.query.filter_by(vigente_desde=vigente_desde).first()
    if versao is None:
        versao = ParametroJornada(vigente_desde=vigente_desde)
        db.session.add(versao)
    for campo, valor in valores.items():
        setattr(versao, campo, ",".join(map(str, valor)) if campo == "dias_trabalho" else valor)
    versao.alterado_por_nome = current_user.nome
    versao.alterado_em = datetime.now(ZoneInfo("America/Sao_Paulo"))
    db.session.commit()
    _limpar_cache_jornada()
    _invalidar_notif_cache()

    data_txt = vigente_desde.strftime("%d/%m/%Y")
    registrar_log(current_user.id, f"Alterou parâmetros de jornada (a partir de {data_txt}): " + "; ".join(mudancas), versao.id)
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    if vigente_desde < hoje:
        flash(f"Regras salvas com vigência retroativa a {data_txt}: os cálculos desde essa data passam a usar as novas regras.", "warning")
    else:
        flash(f"Regras salvas. Valem a partir de {data_txt}.", "success")
    return _redirect_admin("parametros")


# ==========================================
#        AFASTAMENTOS (área do RH)
# ==========================================
def _contexto_afastamentos():
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    todos = (Afastamento.query.options(db.joinedload(Afastamento.usuario))
             .order_by(Afastamento.data_inicio.desc()).limit(300).all())
    return {
        "em_curso": [a for a in todos if a.data_inicio <= hoje <= a.data_fim],
        "proximos": sorted([a for a in todos if a.data_inicio > hoje], key=lambda a: a.data_inicio),
        "anteriores": [a for a in todos if a.data_fim < hoje],
        "colaboradores": Usuario.query.order_by(Usuario.nome.asc()).all(),
        "tipos": AFASTAMENTO_TIPOS,
        "hoje_iso": hoje.isoformat(),
    }


def _ler_anexo_afastamento(arquivo):
    """Valida o anexo pelo conteúdo (não pela extensão). Devolve (nome, tipo, bytes, erro)."""
    if not arquivo or not arquivo.filename:
        return None, None, None, None
    dados = arquivo.read(AFASTAMENTO_ANEXO_MAX + 1)
    if len(dados) > AFASTAMENTO_ANEXO_MAX:
        return None, None, None, "O anexo deve ter no máximo 2 MB."
    tipo = next((mime for assinatura, mime in AFASTAMENTO_ANEXO_TIPOS.items() if dados.startswith(assinatura)), None)
    if tipo is None:
        return None, None, None, "Anexo inválido: envie PDF, JPG ou PNG."
    nome = secure_filename(arquivo.filename)[:200] or "anexo"
    return nome, tipo, dados, None


@app.route("/admin/afastamentos", methods=["GET", "POST"])
@login_required
@rh_required
def admin_afastamentos():
    if request.method == "GET":
        return render_admin_shell(initial_view="afastamentos")

    erros = []
    usuario = None
    try:
        usuario = db.session.get(Usuario, int(request.form.get("usuario_id", "")))
    except ValueError:
        pass
    if usuario is None:
        erros.append("Selecione o colaborador.")
    elif usuario.id == current_user.id:
        erros.append("Você não pode lançar afastamento para si mesmo. Peça a outra pessoa do RH.")
    tipo = request.form.get("tipo", "")
    if tipo not in AFASTAMENTO_TIPOS:
        erros.append("Selecione o tipo de afastamento.")
    try:
        inicio = datetime.strptime(request.form.get("data_inicio", ""), "%Y-%m-%d").date()
        fim = datetime.strptime(request.form.get("data_fim", ""), "%Y-%m-%d").date()
    except ValueError:
        inicio = fim = None
        erros.append("Informe as datas de início e fim.")
    if inicio and fim:
        if fim < inicio:
            erros.append("A data final não pode ser antes da inicial.")
        elif (fim - inicio).days > 365:
            erros.append("Um afastamento pode ter no máximo 1 ano; lance períodos separados se precisar.")
    observacao = (request.form.get("observacao") or "").strip()[:500] or None
    anexo_nome, anexo_tipo, anexo_dados, erro_anexo = _ler_anexo_afastamento(request.files.get("anexo"))
    if erro_anexo:
        erros.append(erro_anexo)
    if not erros and inicio and fim and fechado_no_intervalo(inicio, fim):
        erros.append(msg_mes_fechado(*fechado_no_intervalo(inicio, fim)))
    if not erros and usuario and inicio and fim:
        conflito = Afastamento.query.filter(
            Afastamento.usuario_id == usuario.id,
            Afastamento.data_inicio <= fim,
            Afastamento.data_fim >= inicio,
        ).first()
        if conflito:
            erros.append(
                f"{usuario.nome} já tem {conflito.rotulo.lower()} de {conflito.data_inicio.strftime('%d/%m/%Y')} "
                f"a {conflito.data_fim.strftime('%d/%m/%Y')}, que se sobrepõe a este período."
            )
    if erros:
        for erro in erros:
            flash(erro, "danger")
        return _redirect_admin("afastamentos")

    afast = Afastamento(
        usuario_id=usuario.id, tipo=tipo, data_inicio=inicio, data_fim=fim, observacao=observacao,
        anexo_nome=anexo_nome, anexo_tipo=anexo_tipo, anexo_dados=anexo_dados,
        criado_por_nome=current_user.nome,
    )
    db.session.add(afast)
    db.session.commit()
    _limpar_cache_afastamentos()
    _invalidar_notif_cache(usuario.id)
    periodo = f"{inicio.strftime('%d/%m/%Y')} a {fim.strftime('%d/%m/%Y')}"
    registrar_log(current_user.id, f"Lançou afastamento ({afast.rotulo}) de {usuario.nome}: {periodo}" + (" com anexo" if anexo_dados else ""), afast.id)
    flash(f"{afast.rotulo} de {usuario.nome} lançado(a): {periodo}.", "success")
    return _redirect_admin("afastamentos")


@app.route("/admin/afastamentos/<int:id>/excluir", methods=["POST"])
@login_required
@rh_required
def excluir_afastamento(id):
    afast = Afastamento.query.get_or_404(id)
    if afast.usuario_id == current_user.id:
        flash("Você não pode cancelar o seu próprio afastamento. Peça a outra pessoa do RH.", "danger")
        return _redirect_admin("afastamentos")
    trava = fechado_no_intervalo(afast.data_inicio, afast.data_fim)
    if trava:
        flash(msg_mes_fechado(*trava), "danger")
        return _redirect_admin("afastamentos")
    descricao = (f"{afast.rotulo} de {afast.usuario.nome}: {afast.data_inicio.strftime('%d/%m/%Y')} "
                 f"a {afast.data_fim.strftime('%d/%m/%Y')}")
    uid = afast.usuario_id
    db.session.delete(afast)
    db.session.commit()
    _limpar_cache_afastamentos()
    _invalidar_notif_cache(uid)
    registrar_log(current_user.id, f"Cancelou afastamento ({descricao})", id)
    flash(f"Afastamento cancelado ({descricao}).", "success")
    return _redirect_admin("afastamentos")


@app.route("/admin/afastamentos/<int:id>/anexo")
@login_required
@rh_required
def anexo_afastamento(id):
    afast = Afastamento.query.get_or_404(id)
    if not afast.anexo_dados:
        abort(404)
    registrar_log(current_user.id, f"Abriu o anexo do afastamento ({afast.rotulo}) de {afast.usuario.nome}", id)
    resp = send_file(io.BytesIO(afast.anexo_dados), mimetype=afast.anexo_tipo,
                     as_attachment=True, download_name=afast.anexo_nome or "anexo")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/admin/logs")
@login_required
@ti_required
def admin_logs():
    return render_admin_shell(initial_view="logs")


# Categorias do filtro dos logs: padrões (LIKE, sem diferenciar maiúsculas)
# sobre o texto da ação. Uma ação pode cair em mais de uma categoria.
LOG_CATEGORIAS = {
    "acesso": ("Acessos (login, logout, bloqueios)",
               ["Entrou no sistema%", "Saiu do sistema%", "Falha de login%", "Login bloqueado%"]),
    "senha": ("Senhas", ["%senha%"]),
    "usuarios": ("Usuários, papéis e rostos",
                 ["Cadastrou usuário%", "Excluiu usuário%", "Atualizou o cadastro%", "Alterou papéis%", "%rosto%", "%facial%"]),
    "ponto": ("Ponto, correções e afastamentos",
              ["%ponto%", "%correção%", "%ajuste%", "Aprovou%", "Recusou%", "[AUTOAPROVAÇÃO]%", "%afastamento%"]),
    "fechamento": ("Fechamento do mês", ["%fech%", "%reabr%", "%espelho%"]),
    "parametros": ("Parâmetros, setores, feriados e quiosque",
                   ["Alterou parâmetros%", "%setor%", "%feriado%", "%lembrete%", "%local de trabalho%",
                    "%quiosque%", "Alterou o prazo%", "%região%"]),
}
LOGS_POR_PAGINA = 50


def _contexto_logs(args):
    """Logs de auditoria com busca, autor, categoria, período e paginação."""
    busca = (args.get("q") or "").strip()[:100]
    autor = (args.get("autor") or "").strip()
    categoria = args.get("categoria") or ""
    data_inicio, data_fim = _data_iso(args.get("data_inicio")), _data_iso(args.get("data_fim"))
    pagina = max(1, args.get("pagina", 1, type=int) or 1)

    query = LogAuditoria.query
    if busca:
        termo = f"%{busca}%"
        query = query.filter(db.or_(LogAuditoria.acao.ilike(termo), LogAuditoria.usuario_nome.ilike(termo)))
    if autor == "sistema":
        query = query.filter(LogAuditoria.usuario_id.is_(None))
    elif autor.isdigit():
        query = query.filter(LogAuditoria.usuario_id == int(autor))
    if categoria in LOG_CATEGORIAS:
        query = query.filter(db.or_(*[LogAuditoria.acao.ilike(p) for p in LOG_CATEGORIAS[categoria][1]]))
    if data_inicio:
        query = query.filter(LogAuditoria.data_criacao >= datetime.combine(data_inicio, datetime.min.time()))
    if data_fim:
        query = query.filter(LogAuditoria.data_criacao < datetime.combine(data_fim + timedelta(days=1), datetime.min.time()))

    total = query.count()
    paginas = max(1, -(-total // LOGS_POR_PAGINA))
    pagina = min(pagina, paginas)
    logs = (query.order_by(LogAuditoria.data_criacao.desc(), LogAuditoria.id.desc())
            .offset((pagina - 1) * LOGS_POR_PAGINA).limit(LOGS_POR_PAGINA).all())
    return {
        "logs": logs,
        "total": total,
        "pagina": pagina,
        "paginas": paginas,
        "filtros": {"q": busca, "autor": autor, "categoria": categoria,
                    "data_inicio": data_inicio.isoformat() if data_inicio else "",
                    "data_fim": data_fim.isoformat() if data_fim else ""},
        "filtrando": bool(busca or autor or categoria in LOG_CATEGORIAS or data_inicio or data_fim),
        "categorias": {k: v[0] for k, v in LOG_CATEGORIAS.items()},
        "autores": Usuario.query.order_by(Usuario.nome.asc()).all(),
    }

@app.route('/admin/exportar-afd')
@login_required
@rh_required
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
@rh_required
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
@ti_required
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
@ti_required
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
@ti_required
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
@ti_required
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
@ti_required
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
@rh_required
def enviar_lembrete_geral():
    mensagem = request.form.get("mensagem", "").strip()

    if mensagem:
        # Busca todos os usuários do sistema
        usuarios = Usuario.query.all()

        mensagem = mensagem[:1000]
        for user in usuarios:
            nova_notificacao = Notificacao(
                usuario_id=user.id,
                titulo="Lembrete da Administração",
                mensagem=mensagem,
                tipo="info",
                link=url_for("index"),
            )
            db.session.add(nova_notificacao)

        db.session.commit()
        _invalidar_notif_cache()
        com_aparelho = {uid for (uid,) in db.session.query(PushInscricao.usuario_id).distinct().all()}
        _enviar_push_em_massa(sorted(com_aparelho), "Lembrete da Administração", mensagem)
        registrar_log(current_user.id, f"Enviou lembrete geral para {len(usuarios)} colaborador(es): {mensagem[:120]}")
        detalhe = f" {len(com_aparelho)} também recebe(m) no celular." if com_aparelho else ""
        flash(f"Lembrete enviado para {len(usuarios)} colaborador(es); aparece no sino do app.{detalhe}", 'success')
    else:
        flash('A mensagem do lembrete não pode estar vazia.', 'warning')

    return _redirect_admin("painel")

@app.route("/notificacoes/<int:id>/abrir")
@login_required
def abrir_notificacao(id):
    """Marca o aviso como lido e segue para o destino dele."""
    n = Notificacao.query.filter_by(id=id, usuario_id=current_user.id).first_or_404()
    if not n.lida:
        n.lida = True
        db.session.commit()
        _invalidar_notif_cache(current_user.id)
    return redirect(_internal_path(n.link or "", url_for("index")))


@app.route("/notificacoes/marcar-lidas", methods=["POST"])
@login_required
def marcar_notificacoes_lidas():
    Notificacao.query.filter_by(usuario_id=current_user.id, lida=False).update({"lida": True})
    db.session.commit()
    _invalidar_notif_cache(current_user.id)
    return redirect(_internal_referrer_path(url_for("index")))


def _enviar_push_em_massa(usuario_ids, titulo, corpo):
    """Envia push para vários usuários sem segurar a requisição."""
    if not usuario_ids or VAPID is None:
        return

    def tarefa():
        with app.app_context():
            for uid in usuario_ids:
                try:
                    enviar_push(uid, titulo, corpo, url="/", tag="aviso-geral")
                except Exception:
                    app.logger.exception("Falha no push em massa para %s", uid)

    if app.config.get("TESTING"):
        tarefa()
    else:
        threading.Thread(target=tarefa, name="push-em-massa", daemon=True).start()


# ==========================================
#   FECHAMENTO DO MÊS E ESPELHO DE PONTO
# ==========================================
def _periodo_mes(ano, mes):
    return date(ano, mes, 1), date(ano, mes, calendar.monthrange(ano, mes)[1])


def _ler_mes(valor):
    """'2026-10' -> (2026, 10) ou None."""
    try:
        ano, mes = (int(x) for x in (valor or "").split("-")[:2])
        if 2000 <= ano <= 2100 and 1 <= mes <= 12:
            return ano, mes
    except ValueError:
        pass
    return None


def _snapshot_espelho(usuario, ano, mes):
    """Gera o conteúdo (JSON) e o hash do espelho do mês para um colaborador."""
    import json as _json
    inicio, fim = _periodo_mes(ano, mes)
    dados = _gerar_relatorio_ponto_dados(usuario, inicio.isoformat(), fim.isoformat())
    conteudo = {
        "usuario": usuario.nome,
        "email": usuario.email,
        "setor": usuario.departamento_rel.nome if usuario.departamento_rel else None,
        "contrato": usuario.tipo_contrato or "CLT",
        "inicio": inicio.isoformat(),
        "fim": fim.isoformat(),
        "is_pj": dados["is_pj"],
        "max_pares": dados["max_pares"],
        "tabela_linhas": dados["tabela_linhas"],
        "totais": dados["totais"],
        "total_dias_afastados": dados["total_dias_afastados"],
    }
    texto = _json.dumps(conteudo, ensure_ascii=False, sort_keys=True)
    return texto, hashlib.sha256(texto.encode("utf-8")).hexdigest()


def _contexto_fechamento(mes_param=None):
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    fechamentos = {(f.ano, f.mes): f for f in FechamentoMes.query.all()}
    # Meses listados: últimos 12 meses já terminados + qualquer mês com fechamento.
    meses = set(fechamentos)
    ref = hoje.replace(day=1)
    for _ in range(12):
        ref = (ref - timedelta(days=1)).replace(day=1)
        meses.add((ref.year, ref.month))
    lista = []
    for ano, mes in sorted(meses, reverse=True):
        f = fechamentos.get((ano, mes))
        espelhos = f.espelhos if f else []
        lista.append({
            "ano": ano, "mes": mes, "chave": f"{ano}-{mes:02d}",
            "rotulo": f"{MESES_PT[mes - 1].capitalize()}/{ano}",
            "fech": f,
            "fechado": bool(f and f.fechado),
            "cientes": sum(1 for e in espelhos if e.ciencia_status == "ciente"),
            "contestados": sum(1 for e in espelhos if e.ciencia_status == "contestado"),
            "total": len(espelhos),
        })
    ctx = {"meses": lista, "detalhe": None, "fmt_hhmm": fmt_hhmm}

    sel = _ler_mes(mes_param)
    if sel:
        ano, mes = sel
        inicio, fim = _periodo_mes(ano, mes)
        f = fechamentos.get((ano, mes))
        linhas = []
        if f and f.fechado:
            for e in sorted(f.espelhos, key=lambda e: (e.usuario_nome or "").lower()):
                c = e.conteudo
                linhas.append({"nome": e.usuario_nome, "setor": c.get("setor"), "contrato": c.get("contrato"),
                               "tot": c["totais"], "afastados": c.get("total_dias_afastados", 0), "espelho": e})
        else:
            for u in Usuario.query.order_by(Usuario.nome.asc()).all():
                if u.data_cadastro and u.data_cadastro.date() > fim:
                    continue
                dados = _gerar_relatorio_ponto_dados(u, inicio.isoformat(), fim.isoformat())
                linhas.append({"nome": u.nome, "setor": u.departamento_rel.nome if u.departamento_rel else None,
                               "contrato": u.tipo_contrato or "CLT", "tot": dados["totais"],
                               "afastados": dados["total_dias_afastados"], "espelho": None})
        pendentes_sol = sum(
            1 for s_ in SolicitacaoCorrecao.query.filter_by(status="Pendente").all()
            if (s_.data_ponto or "").endswith(f"/{mes:02d}/{ano}")
        )
        ctx["detalhe"] = {
            "ano": ano, "mes": mes, "chave": f"{ano}-{mes:02d}",
            "rotulo": f"{MESES_PT[mes - 1]}/{ano}",
            "fech": f, "fechado": bool(f and f.fechado),
            "pode_fechar": fim < hoje,
            "linhas": linhas,
            "incompletos": sum(l["tot"]["incompletos"] for l in linhas),
            "solicitacoes_pendentes": pendentes_sol,
        }
    return ctx


@app.route("/admin/fechamento")
@login_required
@rh_required
def admin_fechamento():
    return render_admin_shell(initial_view="fechamento")


@app.route("/admin/fechamento/<int:ano>/<int:mes>/fechar", methods=["POST"])
@login_required
@rh_required
def fechar_mes(ano, mes):
    if not 1 <= mes <= 12:
        abort(404)
    inicio, fim = _periodo_mes(ano, mes)
    hoje = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
    if fim >= hoje:
        flash("Só é possível fechar um mês depois que ele terminar.", "danger")
        return redirect(url_for("admin_fechamento", mes=f"{ano}-{mes:02d}"))
    f = FechamentoMes.query.filter_by(ano=ano, mes=mes).first()
    if f and f.fechado:
        flash("Este mês já está fechado.", "info")
        return redirect(url_for("admin_fechamento", mes=f"{ano}-{mes:02d}"))
    if f is None:
        f = FechamentoMes(ano=ano, mes=mes)
        db.session.add(f)
        db.session.flush()
    existentes = {e.usuario_id: e for e in f.espelhos}
    novos_avisos = []
    for u in Usuario.query.all():
        if u.data_cadastro and u.data_cadastro.date() > fim:
            continue
        texto, h = _snapshot_espelho(u, ano, mes)
        e = existentes.get(u.id)
        if e is None:
            e = EspelhoMensal(fechamento_id=f.id, usuario_id=u.id)
            db.session.add(e)
        mudou = e.hash != h
        e.usuario_nome, e.dados, e.hash = u.nome, texto, h
        if mudou and e.ciencia_status != "pendente":
            # Conteúdo mudou depois de reaberto: precisa de nova ciência.
            e.ciencia_status, e.comentario = "pendente", None
        if e.ciencia_status == "pendente":
            novos_avisos.append(u.id)
    f.fechado = True
    f.fechado_em = datetime.now(ZoneInfo("America/Sao_Paulo"))
    f.fechado_por_nome = current_user.nome
    rotulo = f"{MESES_PT[mes - 1]}/{ano}"
    for uid in novos_avisos:
        db.session.add(Notificacao(usuario_id=uid, titulo=f"Espelho de ponto de {rotulo}",
                                   mensagem="O mês foi fechado. Confira seu espelho e confirme a ciência.",
                                   tipo="info", link=url_for("ver_espelho", ano=ano, mes=mes)))
    db.session.commit()
    _limpar_cache_fechamento()
    _invalidar_notif_cache()
    com_aparelho = {uid for (uid,) in db.session.query(PushInscricao.usuario_id).filter(PushInscricao.usuario_id.in_(novos_avisos)).distinct().all()} if novos_avisos else set()
    _enviar_push_em_massa(sorted(com_aparelho), f"Espelho de ponto de {rotulo}", "O mês foi fechado. Confira seu espelho e confirme a ciência.")
    registrar_log(current_user.id, f"Fechou o mês {rotulo} ({len(f.espelhos)} espelho(s))", f.id)
    flash(f"Mês {rotulo} fechado. {len(novos_avisos)} colaborador(es) foram avisados para dar ciência.", "success")
    return redirect(url_for("admin_fechamento", mes=f"{ano}-{mes:02d}"))


@app.route("/admin/fechamento/<int:ano>/<int:mes>/reabrir", methods=["POST"])
@login_required
@rh_required
def reabrir_mes(ano, mes):
    f = FechamentoMes.query.filter_by(ano=ano, mes=mes, fechado=True).first_or_404()
    motivo = (request.form.get("motivo") or "").strip()
    if len(motivo) < 5:
        flash("Informe o motivo da reabertura (fica registrado no log).", "danger")
        return redirect(url_for("admin_fechamento", mes=f"{ano}-{mes:02d}"))
    f.fechado = False
    f.reaberto_em = datetime.now(ZoneInfo("America/Sao_Paulo"))
    f.reaberto_por_nome = current_user.nome
    f.motivo_reabertura = motivo[:500]
    db.session.commit()
    _limpar_cache_fechamento()
    registrar_log(current_user.id, f"Reabriu o mês {f.rotulo}. Motivo: {motivo[:300]}", f.id)
    flash(f"Mês {f.rotulo} reaberto para ajustes. Feche novamente ao terminar.", "warning")
    return redirect(url_for("admin_fechamento", mes=f"{ano}-{mes:02d}"))


@app.route("/admin/fechamento/<int:ano>/<int:mes>/exportar")
@login_required
@rh_required
def exportar_fechamento(ano, mes):
    """Consolidado do mês fechado para a contabilidade (Excel ou CSV)."""
    import pandas as pd
    f = FechamentoMes.query.filter_by(ano=ano, mes=mes, fechado=True).first_or_404()
    formato = request.args.get("format", "excel")
    dec = lambda seg: round((seg or 0) / 3600, 2)
    linhas = []
    for e in sorted(f.espelhos, key=lambda e: (e.usuario_nome or "").lower()):
        c = e.conteudo
        t = c["totais"]
        linhas.append({
            "Colaborador": c["usuario"], "E-mail": c["email"], "Setor": c.get("setor") or "",
            "Contrato": c.get("contrato") or "CLT",
            "Trabalhado (h)": dec(t["trabalhado"]), "Trabalhado (HH:MM)": fmt_hhmm(t["trabalhado"]),
            f"Extras {t['extra_util_pct']}% (h)": dec(t["extra_50"]), f"Extras {t['extra_util_pct']}% (HH:MM)": fmt_hhmm(t["extra_50"]),
            f"Extras {t['extra_descanso_pct']}% (h)": dec(t["extra_100"]), f"Extras {t['extra_descanso_pct']}% (HH:MM)": fmt_hhmm(t["extra_100"]),
            "Atrasos (h)": dec(t["atraso"]), "Atrasos (HH:MM)": fmt_hhmm(t["atraso"]),
            "Faltas (dias)": t["faltas_dias"], "Faltas (h)": dec(t["falta_seg"]),
            "Adicional noturno (h)": dec(t["noturno_ficto"]) if t.get("noturno_ativo") else 0,
            "Afastados (dias)": c.get("total_dias_afastados", 0),
            "Dias incompletos": t["incompletos"],
            "Ciência": e.ciencia_status,
            "Ciência em": e.ciencia_em.strftime("%d/%m/%Y %H:%M") if e.ciencia_em else "",
            "Código do espelho": e.hash[:12],
        })
    # Protege só textos contra injeção de fórmula; números seguem numéricos (somáveis no Excel).
    seguro = lambda v: _neutralise_export_value(v) if isinstance(v, str) else v
    df = pd.DataFrame([[seguro(v) for v in r.values()] for r in linhas] if linhas else [],
                      columns=list(linhas[0].keys()) if linhas else ["Colaborador"])
    nome = f"Fechamento_{ano}-{mes:02d}"
    registrar_log(current_user.id, f"Exportou o fechamento de {f.rotulo} ({formato})", f.id)
    if formato == "csv":
        out = io.StringIO()
        df.to_csv(out, index=False, sep=";", decimal=",", encoding="utf-8-sig")
        return send_file(io.BytesIO(out.getvalue().encode("utf-8-sig")), as_attachment=True,
                         download_name=f"{nome}.csv", mimetype="text/csv")
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=f"{mes:02d}-{ano}")
    out.seek(0)
    return send_file(out, as_attachment=True, download_name=f"{nome}.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ---------- Espelho do colaborador ----------
def _espelho_do_usuario(ano, mes):
    return (EspelhoMensal.query.join(FechamentoMes)
            .filter(EspelhoMensal.usuario_id == current_user.id, FechamentoMes.ano == ano,
                    FechamentoMes.mes == mes, FechamentoMes.fechado.is_(True))
            .first_or_404())


@app.route("/espelhos")
@login_required
def meus_espelhos():
    espelhos = (EspelhoMensal.query.join(FechamentoMes)
                .filter(EspelhoMensal.usuario_id == current_user.id, FechamentoMes.fechado.is_(True))
                .order_by(FechamentoMes.ano.desc(), FechamentoMes.mes.desc()).all())
    return render_template("espelhos.html", espelhos=espelhos, fmt_hhmm=fmt_hhmm)


@app.route("/espelho/<int:ano>/<int:mes>")
@login_required
def ver_espelho(ano, mes):
    e = _espelho_do_usuario(ano, mes)
    return render_template("espelho.html", e=e, c=e.conteudo, fmt_hhmm=fmt_hhmm)


@app.route("/espelho/<int:ano>/<int:mes>/pdf")
@login_required
def espelho_pdf(ano, mes):
    e = _espelho_do_usuario(ano, mes)
    c = e.conteudo
    dados = {
        "usuario": current_user, "is_pj": c["is_pj"],
        "data_inicio_obj": date.fromisoformat(c["inicio"]), "data_fim_obj": date.fromisoformat(c["fim"]),
        "tabela_linhas": c["tabela_linhas"], "max_pares": c["max_pares"], "totais": c["totais"],
        "total_dias_afastados": c.get("total_dias_afastados", 0),
        "rodape": f"Espelho do fechamento de {e.fechamento.rotulo} · código {e.hash[:12]}",
    }
    return _gerar_arquivo_folha_ponto(dados, "pdf")


@app.route("/espelho/<int:ano>/<int:mes>/ciencia", methods=["POST"])
@login_required
def dar_ciencia_espelho(ano, mes):
    e = _espelho_do_usuario(ano, mes)
    acao = request.form.get("acao")
    comentario = (request.form.get("comentario") or "").strip()[:1000]
    if acao not in ("ciente", "contestar"):
        abort(400)
    if acao == "contestar" and len(comentario) < 5:
        flash("Explique o que está errado para o RH poder verificar.", "danger")
        return redirect(url_for("ver_espelho", ano=ano, mes=mes))
    e.ciencia_status = "ciente" if acao == "ciente" else "contestado"
    e.comentario = comentario or None
    e.ciencia_em = datetime.now(ZoneInfo("America/Sao_Paulo"))
    e.ciencia_ip = (request.remote_addr or "")[:64]
    e.ciencia_user_agent = (request.headers.get("User-Agent") or "")[:255]
    e.ciencia_hash = e.hash
    db.session.commit()
    _invalidar_notif_cache(current_user.id)
    registrar_log(current_user.id, f"{'Deu ciência no' if acao == 'ciente' else 'Contestou o'} espelho de {e.fechamento.rotulo}"
                  + (f": {comentario[:200]}" if acao == "contestar" else ""), e.id)
    flash("Ciência registrada. Obrigado!" if acao == "ciente" else "Contestação enviada ao RH.", "success")
    return redirect(url_for("ver_espelho", ano=ano, mes=mes))


# ==========================================
#   NOTIFICAÇÕES PUSH E LEMBRETES DE PONTO
# ==========================================
def _carregar_vapid():
    """Valida o par VAPID do ambiente; sem par válido o push fica desligado."""
    pub = (os.environ.get("VAPID_PUBLIC_KEY") or "").strip()
    priv = (os.environ.get("VAPID_PRIVATE_KEY") or "").strip()
    claim = (os.environ.get("VAPID_CLAIM_EMAIL") or "").strip()
    if not (pub and priv and claim):
        return None
    try:
        import base64
        from py_vapid import Vapid02
        from cryptography.hazmat.primitives import serialization
        derivada = base64.urlsafe_b64encode(
            Vapid02.from_raw(priv.encode()).public_key.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        ).rstrip(b"=").decode()
        if derivada != pub:
            app.logger.warning("VAPID_PUBLIC_KEY não corresponde à VAPID_PRIVATE_KEY: push desligado.")
            return None
    except Exception as exc:
        app.logger.warning("Chaves VAPID inválidas, push desligado: %s", exc)
        return None
    return {"publica": pub, "privada": priv, "claim": claim if claim.startswith("mailto:") else f"mailto:{claim}"}


VAPID = _carregar_vapid()
if VAPID is None:
    print("AVISO: chaves VAPID ausentes ou inválidas. Notificações push desligadas.")

LEMBRETE_JANELA_MIN = 4  # tolera atrasos do verificador sem enviar dois lembretes juntos


def config_lembretes():
    """Parâmetros de lembrete definidos pela TI (Configuracao)."""
    def inteiro(chave, padrao, minimo, maximo):
        try:
            return max(minimo, min(maximo, int(_get_config(chave, padrao))))
        except (TypeError, ValueError):
            return padrao
    antecedencias = sorted({inteiro("lembrete_antecedencia_1", 10, 0, 60), inteiro("lembrete_antecedencia_2", 5, 0, 60)} - {0}, reverse=True)
    return {
        "ativos": (_get_config("lembretes_ativos", "true") or "true").lower() == "true",
        "antecedencias": antecedencias,
        "esquecimento_min": inteiro("lembrete_esquecimento_min", 15, 5, 120),
    }


def enviar_push(usuario_id, titulo, corpo, url="/", tag=None):
    """Envia push a todos os aparelhos do usuário; remove inscrições expiradas."""
    if VAPID is None:
        return 0
    from pywebpush import webpush, WebPushException
    import json as _json
    enviados = 0
    payload = _json.dumps({"titulo": titulo, "corpo": corpo, "url": url, "tag": tag or "ponto"})
    for insc in PushInscricao.query.filter_by(usuario_id=usuario_id).all():
        try:
            webpush(
                subscription_info={"endpoint": insc.endpoint, "keys": {"p256dh": insc.p256dh, "auth": insc.auth}},
                data=payload,
                vapid_private_key=VAPID["privada"],
                vapid_claims={"sub": VAPID["claim"]},
                ttl=900,
                timeout=10,
            )
            enviados += 1
        except WebPushException as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in (404, 410):
                db.session.delete(insc)  # aparelho desinscrito/expirado
                db.session.commit()
            else:
                app.logger.warning("Falha no push para usuário %s: %s", usuario_id, exc)
        except Exception as exc:
            app.logger.warning("Falha no push para usuário %s: %s", usuario_id, exc)
    return enviados


def lembretes_devidos(agora=None):
    """Lista os lembretes que deveriam sair agora (sem considerar os já enviados)."""
    cfg = config_lembretes()
    if not cfg["ativos"]:
        return []
    agora = agora or datetime.now(ZoneInfo("America/Sao_Paulo"))
    hoje = agora.date()
    minuto = agora.hour * 60 + agora.minute
    hoje_str = hoje.strftime("%d/%m/%Y")

    batidas = defaultdict(list)
    for r in RegistroPonto.query.filter_by(data=hoje_str).all():
        batidas[r.usuario_id].append((r.hora or "", r.tipo))

    def fmt(m):
        return f"{m // 60:02d}:{m % 60:02d}"

    devidos = []
    for u in Usuario.query.all():
        dep = u.departamento_id
        if not eh_dia_util(hoje, dep) or afastamento_no_dia(u.id, hoje):
            continue
        j = jornada_vigente(hoje, dep)
        entrada, saida = j.horario_entrada_min, j.horario_saida_min
        if entrada is None or saida is None:
            continue
        tipos = [t for _h, t in sorted(batidas.get(u.id, []))]
        tem_entrada = "Entrada" in tipos
        expediente_aberto = bool(tipos) and tipos[-1] == "Entrada"

        for k in cfg["antecedencias"]:
            if not tem_entrada and entrada - k <= minuto < entrada - k + LEMBRETE_JANELA_MIN:
                devidos.append({"usuario": u, "tipo": f"entrada_{k}", "persistir": False,
                                "titulo": f"Expediente começa em {k} min",
                                "corpo": f"Sua entrada é às {fmt(entrada)}. Não esqueça de bater o ponto."})
            if expediente_aberto and saida - k <= minuto < saida - k + LEMBRETE_JANELA_MIN:
                devidos.append({"usuario": u, "tipo": f"saida_{k}", "persistir": False,
                                "titulo": f"Expediente termina em {k} min",
                                "corpo": f"Sua saída é às {fmt(saida)}. Lembre-se de bater o ponto ao sair."})

        esquecimento = entrada + cfg["esquecimento_min"]
        if not tem_entrada and esquecimento <= minuto < saida:
            devidos.append({"usuario": u, "tipo": "esqueceu_entrada", "persistir": True,
                            "titulo": "Você ainda não bateu a entrada",
                            "corpo": f"Seu expediente começou às {fmt(entrada)} e não há registro de entrada hoje."})
    return devidos


def processar_lembretes(agora=None):
    """Envia os lembretes devidos uma única vez (registro único por pessoa/dia/tipo)."""
    from sqlalchemy.exc import IntegrityError
    agora = agora or datetime.now(ZoneInfo("America/Sao_Paulo"))
    enviados = 0
    for item in lembretes_devidos(agora):
        u = item["usuario"]
        db.session.add(LembreteEnviado(usuario_id=u.id, data=agora.date(), tipo=item["tipo"]))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # outro processo/execução já enviou
            continue
        if item["persistir"]:
            db.session.add(Notificacao(usuario_id=u.id, titulo=item["titulo"], mensagem=item["corpo"],
                                       tipo="warning", link=url_for("index") if has_request_context() else "/"))
            db.session.commit()
            _invalidar_notif_cache(u.id)
        enviar_push(u.id, item["titulo"], item["corpo"], url="/", tag=item["tipo"])
        enviados += 1
    return enviados


def _laco_lembretes():
    app.logger.info("Verificador de lembretes de ponto iniciado.")
    while True:
        try:
            with app.app_context():
                processar_lembretes()
        except Exception:
            app.logger.exception("Erro no verificador de lembretes")
        time.sleep(max(5, 60 - datetime.now().second))


_lembretes_lock = threading.Lock()
_lembretes_iniciado = False


def iniciar_verificador_lembretes():
    global _lembretes_iniciado
    with _lembretes_lock:
        if _lembretes_iniciado:
            return
        _lembretes_iniciado = True
    threading.Thread(target=_laco_lembretes, name="lembretes-ponto", daemon=True).start()


@app.before_request
def _garantir_verificador_lembretes():
    # Roda dentro do processo web (padrão). Para um processo separado, defina
    # LEMBRETES_NO_WEB=false e rode `flask --app app lembretes`.
    if not _lembretes_iniciado and not app.config.get("TESTING") and _env_bool("LEMBRETES_NO_WEB", True):
        iniciar_verificador_lembretes()


@app.cli.command("lembretes")
def lembretes_command():
    """Roda o verificador de lembretes em primeiro plano (processo worker)."""
    _laco_lembretes()


# ---------- Service worker e manifesto (PWA) ----------
@app.route("/sw.js")
def service_worker():
    resp = send_from_directory(os.path.join(app.root_path, "static", "js"), "sw.js", mimetype="application/javascript")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/manifest.webmanifest")
def manifesto_pwa():
    dados = {
        "name": "4Lab Orbit | Controle de Ponto",
        "short_name": "Ponto",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": "#030825",  # fundo do ícone (tela de abertura)
        "theme_color": "#0f172a",
        "lang": "pt-BR",
        "icons": [
            {"src": url_for("static", filename="icons/icon-192.png"), "sizes": "192x192", "type": "image/png"},
            {"src": url_for("static", filename="icons/icon-512.png"), "sizes": "512x512", "type": "image/png"},
            {"src": url_for("static", filename="icons/icon-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ],
    }
    resp = jsonify(dados)
    resp.headers["Content-Type"] = "application/manifest+json"
    return resp


# ---------- Inscrição de aparelhos ----------
# O servidor faz POST no endpoint informado pelo navegador; aceitar qualquer
# URL deixaria um colaborador apontar o servidor para hosts arbitrários ou
# lentos (travando o laço de lembretes). Só os serviços de push reais.
_PUSH_HOSTS = ("fcm.googleapis.com", "android.googleapis.com", "web.push.apple.com")
_PUSH_HOST_SUFIXOS = (".push.services.mozilla.com", ".notify.windows.com", ".push.apple.com")
PUSH_MAX_POR_USUARIO = 5


def _endpoint_push_valido(endpoint):
    if not endpoint or len(endpoint) > 2000:
        return False
    try:
        partes = urlparse(endpoint)
        porta = partes.port
    except ValueError:
        return False
    host = (partes.hostname or "").lower()
    if partes.scheme != "https" or partes.username or partes.password or porta not in (None, 443):
        return False
    return host in _PUSH_HOSTS or host.endswith(_PUSH_HOST_SUFIXOS)


@app.route("/api/push/chave")
@login_required
def api_push_chave():
    return jsonify(ativo=VAPID is not None, chave=VAPID["publica"] if VAPID else None,
                   inscritos=PushInscricao.query.filter_by(usuario_id=current_user.id).count())


@app.route("/api/push/inscrever", methods=["POST"])
@login_required
def api_push_inscrever():
    if VAPID is None:
        return jsonify(erro="Notificações push não estão configuradas no servidor."), 503
    dados = request.get_json(silent=True) or {}
    endpoint = str(dados.get("endpoint") or "")
    chaves = dados.get("keys") or {}
    p256dh, auth = str(chaves.get("p256dh") or ""), str(chaves.get("auth") or "")
    if (not _endpoint_push_valido(endpoint) or not p256dh or not auth
            or len(p256dh) > 255 or len(auth) > 255):
        return jsonify(erro="Inscrição inválida."), 400
    h = hashlib.sha256(endpoint.encode()).hexdigest()
    insc = PushInscricao.query.filter_by(endpoint_hash=h).first()
    if insc is None:
        # Limita aparelhos por pessoa: os mais antigos saem primeiro.
        antigas = (PushInscricao.query.filter_by(usuario_id=current_user.id)
                   .order_by(PushInscricao.id.desc()).offset(PUSH_MAX_POR_USUARIO - 1).all())
        for velha in antigas:
            db.session.delete(velha)
        insc = PushInscricao(endpoint=endpoint, endpoint_hash=h)
        db.session.add(insc)
    insc.usuario_id = current_user.id  # aparelho passa a ser de quem está logado
    insc.p256dh, insc.auth = p256dh, auth
    insc.user_agent = (request.headers.get("User-Agent") or "")[:255]
    db.session.commit()
    return jsonify(ok=True)


@app.route("/api/push/cancelar", methods=["POST"])
@login_required
def api_push_cancelar():
    dados = request.get_json(silent=True) or {}
    endpoint = str(dados.get("endpoint") or "")
    h = hashlib.sha256(endpoint.encode()).hexdigest()
    PushInscricao.query.filter_by(endpoint_hash=h, usuario_id=current_user.id).delete()
    db.session.commit()
    return jsonify(ok=True)


@app.route("/api/push/teste", methods=["POST"])
@login_required
def api_push_teste():
    _rate_limit("push_teste", ident=current_user.id)
    n = enviar_push(current_user.id, "Lembretes ativados ✅", "É assim que os lembretes de ponto vão aparecer.", url="/", tag="teste")
    return jsonify(enviados=n)


# ---------- Parâmetros de lembrete (TI) ----------
@app.route("/admin/parametros/lembretes", methods=["POST"])
@login_required
@ti_required
def admin_parametros_lembretes():
    def ler(campo, minimo, maximo):
        try:
            v = int(request.form.get(campo, ""))
        except ValueError:
            return None
        return v if minimo <= v <= maximo else None

    a1, a2 = ler("lembrete_antecedencia_1", 0, 60), ler("lembrete_antecedencia_2", 0, 60)
    esq = ler("lembrete_esquecimento_min", 5, 120)
    if a1 is None or a2 is None or esq is None:
        flash("Lembretes: antecedências de 0 a 60 min e aviso de esquecimento de 5 a 120 min.", "danger")
        return _redirect_admin("parametros", "lembretes")
    novos = {
        "lembretes_ativos": "true" if request.form.get("lembretes_ativos") == "on" else "false",
        "lembrete_antecedencia_1": str(a1),
        "lembrete_antecedencia_2": str(a2),
        "lembrete_esquecimento_min": str(esq),
    }
    padroes = {"lembretes_ativos": "true", "lembrete_antecedencia_1": "10", "lembrete_antecedencia_2": "5", "lembrete_esquecimento_min": "15"}
    mudancas = []
    for chave, valor in novos.items():
        antes = _get_config(chave, padroes[chave])
        if str(antes) != valor:
            mudancas.append(f"{chave}: {antes} -> {valor}")
            _set_config(chave, valor)
    if not mudancas:
        flash("Nenhuma regra foi alterada.", "info")
        return _redirect_admin("parametros", "lembretes")
    db.session.commit()
    registrar_log(current_user.id, "Alterou os lembretes de ponto: " + "; ".join(mudancas))
    flash("Lembretes de ponto atualizados.", "success")
    return _redirect_admin("parametros", "lembretes")


# ==========================================
#   QUIOSQUE DE PONTO (tablet com foto)
# ==========================================
# O quiosque não é uma conta: a TI autoriza um tablet, que guarda um token
# opaco num cookie de longa duração (renovado a cada uso, então não expira
# enquanto estiver em uso). Só um tablet fica ativo por vez. Quem bate o ponto
# se identifica por e-mail ou CPF, confirma o nome e a câmera tira a foto
# quando o rosto encaixa na moldura (detecção no próprio aparelho).

QUIOSQUE_COOKIE = "__Host-ponto_quiosque" if app.config["SESSION_COOKIE_SECURE"] else "ponto_quiosque"
QUIOSQUE_COOKIE_DIAS = 400            # limite dos navegadores; renovado a cada uso
QUIOSQUE_TOKEN_IDENT_SEG = 180        # tempo entre confirmar o nome e enviar a foto
QUIOSQUE_FOTO_MAX_BYTES = 1_500_000
QUIOSQUE_FOTO_LARGURA = 480           # a foto guardada é reduzida (≈20–40 KB)
app.config["RATE_LIMITS"].update({"quiosque_identificar": (40, 300), "quiosque_registrar": (40, 300)})


def _cpf_normalizar(valor):
    """11 dígitos de um CPF válido (confere os dígitos verificadores) ou None."""
    digitos = re.sub(r"\D", "", valor or "")
    if len(digitos) != 11 or digitos == digitos[0] * 11:
        return None
    for tamanho in (9, 10):
        soma = sum(int(d) * (tamanho + 1 - i) for i, d in enumerate(digitos[:tamanho]))
        if int(digitos[tamanho]) != (soma * 10 % 11) % 10:
            return None
    return digitos


def _cpf_mascarado(cpf):
    return f"***.***.{cpf[6:9]}-{cpf[9:]}" if cpf and len(cpf) == 11 else "vazio"


def _quiosque_atual():
    """Tablet autorizado desta requisição (pelo cookie) ou None."""
    # Cache no objeto da requisição (o g pode ser compartilhado por contextos aninhados).
    if hasattr(request, "_quiosque_disp"):
        return request._quiosque_disp
    bruto = request.cookies.get(QUIOSQUE_COOKIE, "")
    disp = None
    if 30 <= len(bruto) <= 200:
        disp = QuiosqueDispositivo.query.filter_by(token_hash=_token_digest(bruto)).first()
    request._quiosque_disp = disp
    return disp


def _quiosque_cookie(resposta, token_bruto):
    resposta.set_cookie(
        QUIOSQUE_COOKIE, token_bruto, max_age=QUIOSQUE_COOKIE_DIAS * 86400, path="/",
        secure=app.config["SESSION_COOKIE_SECURE"], httponly=True, samesite="Strict",
    )
    return resposta


def quiosque_required(f):
    @wraps(f)
    def decorado(*args, **kwargs):
        disp = _quiosque_atual()
        if disp is None:
            if request.path.startswith("/quiosque/api/"):
                return jsonify(erro="Este aparelho não está autorizado como quiosque."), 403
            flash("Este aparelho não está autorizado como quiosque. Peça à TI para ativá-lo.", "warning")
            return redirect(url_for("login"))
        agora = _local_now()
        if disp.ultimo_uso_em is None or agora - disp.ultimo_uso_em > timedelta(minutes=10):
            disp.ultimo_uso_em = agora
            db.session.commit()
        resposta = make_response(f(*args, **kwargs))
        if getattr(request, "_quiosque_encerrado", False):
            return resposta  # saída pelo tablet: o cookie acabou de ser apagado
        # Renova o cookie a cada uso: o quiosque não "cai" enquanto estiver ligado.
        return _quiosque_cookie(resposta, request.cookies[QUIOSQUE_COOKIE])
    return decorado


def _quiosque_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="quiosque-identificacao")


def _quiosque_buscar_pessoa(identificador):
    ident = (identificador or "").strip()
    if "@" in ident:
        return Usuario.query.filter(db.func.lower(Usuario.email) == ident.lower()[:100]).first()
    cpf = _cpf_normalizar(ident)
    return Usuario.query.filter_by(cpf=cpf).first() if cpf else None


def _quiosque_foto_jpeg(arquivo):
    """Valida a foto enviada pela câmera e devolve um JPEG reduzido e limpo."""
    if arquivo is None:
        raise ValueError("A foto não chegou. Tente de novo.")
    dados = arquivo.read(QUIOSQUE_FOTO_MAX_BYTES + 1)
    if not dados or len(dados) > QUIOSQUE_FOTO_MAX_BYTES:
        raise ValueError("Foto inválida. Tente de novo.")
    try:
        with Image.open(io.BytesIO(dados)) as img:
            if img.format not in {"JPEG", "PNG", "WEBP"}:
                raise ValueError
            largura, altura = img.size
            if not (100 <= largura <= 4096 and 100 <= altura <= 4096):
                raise ValueError
            img.verify()
        with Image.open(io.BytesIO(dados)) as img:
            img = ImageOps.exif_transpose(img).convert("RGB")
            if img.width > QUIOSQUE_FOTO_LARGURA:
                img = img.resize((QUIOSQUE_FOTO_LARGURA, round(img.height * QUIOSQUE_FOTO_LARGURA / img.width)), Image.LANCZOS)
            saida = io.BytesIO()
            img.save(saida, format="JPEG", quality=72, optimize=True)  # sem EXIF/metadados
            return saida.getvalue()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise ValueError("Foto inválida. Tente de novo.") from exc


def _primeiro_e_ultimo_nome(nome):
    partes = (nome or "").split()
    return " ".join([partes[0], partes[-1]]) if len(partes) > 1 else (nome or "")


@app.route("/quiosque")
@quiosque_required
def quiosque():
    metodo = _quiosque_metodo()
    # Sem nenhum rosto cadastrado o reconhecimento não teria com quem comparar.
    if metodo == "facial" and RostoCadastrado.query.first() is None:
        metodo = "cpf"
    return render_template("quiosque.html", metodo=metodo)


@app.route("/quiosque/api/estado")
@quiosque_required
def quiosque_estado():
    """Mantém o quiosque vivo e entrega um token CSRF atual (a página fica
    aberta o dia todo; a sessão anônima de 8h por trás dela é renovada aqui)."""
    session.permanent = True
    token = csrf_token()
    session.modified = True  # regrava o cookie: a sessão anônima nunca chega a expirar
    return jsonify(ok=True, csrf=token, hora=_local_now().strftime("%H:%M:%S"))


@app.route("/quiosque/api/identificar", methods=["POST"])
@quiosque_required
def quiosque_identificar():
    _rate_limit("quiosque_identificar", ident=f"q{_quiosque_atual().id}")
    dados = request.get_json(silent=True) or {}
    pessoa = _quiosque_buscar_pessoa(str(dados.get("identificador") or ""))
    if pessoa is None:
        return jsonify(erro="Não encontramos ninguém com esse e-mail ou CPF. Confira e tente de novo."), 404
    hoje = _local_now().strftime("%d/%m/%Y")
    token = _quiosque_serializer().dumps({"u": pessoa.id, "q": _quiosque_atual().id})
    return jsonify(token=token, nome=_primeiro_e_ultimo_nome(pessoa.nome),
                   inicial=(pessoa.nome or "?")[0].upper(), proximo=_proximo_tipo_ponto(pessoa.id, hoje))


@app.route("/quiosque/api/registrar", methods=["POST"])
@quiosque_required
def quiosque_registrar():
    disp = _quiosque_atual()
    _rate_limit("quiosque_registrar", ident=f"q{disp.id}")
    try:
        dados = _quiosque_serializer().loads(request.form.get("token", ""), max_age=QUIOSQUE_TOKEN_IDENT_SEG)
    except (BadSignature, SignatureExpired):
        return jsonify(erro="Tempo esgotado. Comece de novo."), 400
    if not isinstance(dados, dict) or dados.get("q") != disp.id:
        return jsonify(erro="Tempo esgotado. Comece de novo."), 400
    pessoa = db.session.get(Usuario, dados.get("u"))
    if pessoa is None:
        return jsonify(erro="Cadastro não encontrado. Fale com o RH."), 404
    try:
        foto = _quiosque_foto_jpeg(request.files.get("foto"))
    except ValueError as exc:
        return jsonify(erro=str(exc)), 400
    registro, erro = _registrar_proximo_ponto(pessoa.id, foto_jpeg=foto)
    if erro:
        return jsonify(erro=erro), 409 if "recentemente" in erro else 500
    return jsonify(ok=True, tipo=registro.tipo, hora=registro.hora[:5],
                   nome=_primeiro_e_ultimo_nome(pessoa.nome))


# ---------- Reconhecimento facial no quiosque ----------
# O aparelho calcula o descritor (128 números) com a face-api; o servidor só
# compara descritores. Distância euclidiana: < 0,6 é "provavelmente a mesma
# pessoa" na literatura do modelo; usamos 0,5 e exigimos folga para o segundo
# colocado, preferindo "não reconheci" a confundir duas pessoas.
QUIOSQUE_METODOS = {"cpf": "CPF ou e-mail", "facial": "Reconhecimento facial"}
FACIAL_LIMIAR = 0.50
FACIAL_FOLGA = 0.06
FACIAL_AMOSTRAS_MAX = 5


def _quiosque_metodo():
    metodo = _get_config("quiosque_metodo", "cpf")
    return metodo if metodo in QUIOSQUE_METODOS else "cpf"


def _descritor_valido(valor):
    """Lista de 128 números finitos e com tamanho plausível -> bytes float32."""
    if not isinstance(valor, list) or len(valor) != 128:
        return None
    try:
        nums = [float(x) for x in valor]
    except (TypeError, ValueError):
        return None
    if not all(math.isfinite(x) and -2.0 < x < 2.0 for x in nums):
        return None
    norma = math.sqrt(sum(x * x for x in nums))
    if not 0.3 < norma < 3.0:
        return None
    return struct.pack("<128f", *nums)


def _descritor_lista(dados):
    return struct.unpack("<128f", dados)


def _reconhecer_rosto(descritor_bytes):
    """(usuario, distância) da pessoa reconhecida, ou (None, melhor distância)."""
    alvo = _descritor_lista(descritor_bytes)
    melhor_por_usuario = {}
    for rosto in RostoCadastrado.query.all():
        cad = _descritor_lista(rosto.descritor)
        d = math.sqrt(sum((a - b) ** 2 for a, b in zip(alvo, cad)))
        if d < melhor_por_usuario.get(rosto.usuario_id, 99):
            melhor_por_usuario[rosto.usuario_id] = d
    if not melhor_por_usuario:
        return None, None
    ordenado = sorted(melhor_por_usuario.items(), key=lambda kv: kv[1])
    uid, melhor = ordenado[0]
    segundo = ordenado[1][1] if len(ordenado) > 1 else 99
    if melhor <= FACIAL_LIMIAR and segundo - melhor >= FACIAL_FOLGA:
        return db.session.get(Usuario, uid), melhor
    return None, melhor


@app.route("/quiosque/api/reconhecer", methods=["POST"])
@quiosque_required
def quiosque_reconhecer():
    disp = _quiosque_atual()
    _rate_limit("quiosque_identificar", ident=f"q{disp.id}")
    descritor = _descritor_valido((request.get_json(silent=True) or {}).get("descritor"))
    if descritor is None:
        return jsonify(erro="Não foi possível ler o rosto. Tente de novo."), 400
    pessoa, distancia = _reconhecer_rosto(descritor)
    if pessoa is None:
        return jsonify(erro="Não reconhecemos você. Tente de novo ou use o CPF."), 404
    hoje = _local_now().strftime("%d/%m/%Y")
    token = _quiosque_serializer().dumps({"u": pessoa.id, "q": disp.id, "f": round(distancia, 3)})
    return jsonify(token=token, nome=_primeiro_e_ultimo_nome(pessoa.nome),
                   inicial=(pessoa.nome or "?")[0].upper(), proximo=_proximo_tipo_ponto(pessoa.id, hoje))


@app.route("/admin/usuarios/<int:user_id>/rosto", methods=["POST"])
@login_required
@ti_required
def admin_cadastrar_rosto(user_id):
    user = Usuario.query.get_or_404(user_id)
    dados = request.get_json(silent=True) or {}
    if dados.get("consentimento") is not True:
        return jsonify(erro="Confirme que a pessoa autorizou o uso da biometria facial."), 400
    amostras = dados.get("descritores")
    if not isinstance(amostras, list) or not 1 <= len(amostras) <= FACIAL_AMOSTRAS_MAX:
        return jsonify(erro="Amostras do rosto inválidas. Tente de novo."), 400
    blobs = [_descritor_valido(a) for a in amostras]
    if any(b is None for b in blobs):
        return jsonify(erro="Amostras do rosto inválidas. Tente de novo."), 400
    agora = _local_now()
    RostoCadastrado.query.filter_by(usuario_id=user.id).delete()
    for b in blobs:
        db.session.add(RostoCadastrado(usuario_id=user.id, descritor=b, consentimento_em=agora,
                                       criado_por_nome=current_user.nome))
    db.session.commit()
    registrar_log(current_user.id, f"Cadastrou o rosto de {user.nome} para o quiosque ({len(blobs)} amostras, com consentimento)", user.id)
    return jsonify(ok=True, amostras=len(blobs))


@app.route("/admin/usuarios/<int:user_id>/rosto/excluir", methods=["POST"])
@login_required
@ti_required
def admin_excluir_rosto(user_id):
    user = Usuario.query.get_or_404(user_id)
    n = RostoCadastrado.query.filter_by(usuario_id=user.id).delete()
    db.session.commit()
    if n:
        registrar_log(current_user.id, f"Excluiu o cadastro facial de {user.nome}", user.id)
        flash(f"Cadastro facial de {user.nome} excluído.", "success")
    else:
        flash(f"{user.nome} não tinha rosto cadastrado.", "info")
    return _redirect_admin("usuarios")


@app.route("/admin/parametros/quiosque-metodo", methods=["POST"])
@login_required
@ti_required
def admin_quiosque_metodo():
    metodo = request.form.get("quiosque_metodo", "")
    if metodo not in QUIOSQUE_METODOS:
        flash("Método inválido.", "danger")
        return _redirect_admin("parametros", "quiosque")
    antes = _quiosque_metodo()
    if metodo != antes:
        _set_config("quiosque_metodo", metodo)
        db.session.commit()
        registrar_log(current_user.id, f"Alterou a identificação do quiosque: {QUIOSQUE_METODOS[antes]} -> {QUIOSQUE_METODOS[metodo]}")
        flash(f"Quiosque agora identifica por {QUIOSQUE_METODOS[metodo].lower()}.", "success")
    return _redirect_admin("parametros", "quiosque")


@app.route("/admin/parametros/local", methods=["POST"])
@login_required
@ti_required
def admin_parametros_local():
    """Raio do local de trabalho: fora dele, a batida pelo app é recusada."""
    ativo = request.form.get("geo_ativo") == "on"
    try:
        lat = float((request.form.get("geo_lat") or "").replace(",", "."))
        lon = float((request.form.get("geo_lon") or "").replace(",", "."))
        raio = int(request.form.get("geo_raio_m", ""))
    except ValueError:
        if ativo:
            flash("Informe latitude, longitude e raio válidos (use \"Usar minha localização atual\").", "danger")
            return _redirect_admin("parametros", "local")
        lat = lon = None
        raio = int(_get_config("geo_raio_m", "200"))
    if lat is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180):
        flash("Latitude ou longitude fora do intervalo válido.", "danger")
        return _redirect_admin("parametros", "local")
    if not (GEO_RAIO_MIN <= raio <= GEO_RAIO_MAX):
        flash(f"O raio deve ficar entre {GEO_RAIO_MIN} m e {GEO_RAIO_MAX} m.", "danger")
        return _redirect_admin("parametros", "local")

    novos = {"geo_ativo": "true" if ativo else "false", "geo_raio_m": str(raio)}
    if lat is not None:
        novos.update(geo_lat=f"{lat:.6f}", geo_lon=f"{lon:.6f}")
    rotulos = {"geo_ativo": "ativo", "geo_lat": "latitude", "geo_lon": "longitude", "geo_raio_m": "raio (m)"}
    mudancas = []
    for chave, valor in novos.items():
        antes = _get_config(chave, "")
        if antes != valor:
            mudancas.append(f"{rotulos[chave]}: {antes or 'vazio'} -> {valor}")
            _set_config(chave, valor)
    if not mudancas:
        flash("Nada foi alterado no local de trabalho.", "info")
        return _redirect_admin("parametros", "local")
    db.session.commit()
    registrar_log(current_user.id, "Alterou o local de trabalho (raio da batida): " + "; ".join(mudancas))
    flash("Local de trabalho atualizado." + ("" if ativo else " A verificação de raio está desligada."), "success")
    return _redirect_admin("parametros", "local")


@app.route("/quiosque/api/sair", methods=["POST"])
@quiosque_required
def quiosque_sair():
    """Saída escondida do próprio tablet: exige e-mail e senha de uma conta
    da TI (com o mesmo bloqueio por tentativas do login) e desativa o quiosque."""
    _rate_limit("login")
    dados = request.get_json(silent=True) or {}
    email = str(dados.get("email") or "").strip().lower()[:254]
    senha = str(dados.get("senha") or "")
    email_hash = hashlib.sha256(email.encode()).hexdigest()
    if _conta_bloqueada(email_hash):
        return jsonify(erro=f"Muitas tentativas. Aguarde {LOGIN_BLOQUEIO_MIN} minutos."), 429
    user = Usuario.query.filter(db.func.lower(Usuario.email) == email).first()
    valido = check_password_hash(user.senha_hash if user else DUMMY_PASSWORD_HASH, senha)
    if not (valido and user is not None and user.is_ti):
        _registrar_falha_login(email_hash)
        registrar_log(user.id if user else None,
                      f"Tentativa de sair do quiosque recusada: {email} (IP {request.remote_addr})")
        return jsonify(erro="E-mail ou senha incorretos, ou a conta não é da TI."), 401
    TentativaLogin.query.filter_by(email_hash=email_hash).delete()
    QuiosqueDispositivo.query.delete()
    db.session.commit()
    registrar_log(user.id, "Desativou o quiosque pelo próprio tablet", user.id)
    request._quiosque_encerrado = True
    resposta = jsonify(ok=True)
    resposta.delete_cookie(QUIOSQUE_COOKIE, path="/", secure=app.config["SESSION_COOKIE_SECURE"],
                           httponly=True, samesite="Strict")
    return resposta


@app.route("/admin/quiosque/ativar", methods=["POST"])
@login_required
@ti_required
def admin_quiosque_ativar():
    """Transforma ESTE aparelho no quiosque: grava o token, encerra a sessão
    de quem ativou (o tablet não fica logado na conta da TI) e abre a tela."""
    QuiosqueDispositivo.query.delete()  # só um tablet ativo por vez
    token = secrets.token_urlsafe(32)
    db.session.add(QuiosqueDispositivo(token_hash=_token_digest(token), criado_por_nome=current_user.nome))
    db.session.commit()
    registrar_log(current_user.id, "Ativou o quiosque de ponto neste aparelho (o anterior, se havia, foi desativado)")
    logout_user()
    session.clear()
    return _quiosque_cookie(redirect(url_for("quiosque")), token)


@app.route("/admin/quiosque/desativar", methods=["POST"])
@login_required
@ti_required
def admin_quiosque_desativar():
    n = QuiosqueDispositivo.query.delete()
    db.session.commit()
    if n:
        registrar_log(current_user.id, "Desativou o quiosque de ponto")
        flash("Quiosque desativado. O tablet volta para a tela de login.", "success")
    else:
        flash("Não havia quiosque ativo.", "info")
    return _redirect_admin("parametros", "quiosque")


def _ids_com_foto(registros):
    """Ids dos registros (da lista) que têm foto do quiosque, numa consulta só."""
    ids = [r.id for r in registros]
    if not ids:
        return set()
    return {rid for (rid,) in db.session.query(FotoPonto.registro_id).filter(FotoPonto.registro_id.in_(ids))}


app.jinja_env.globals["ids_com_foto"] = _ids_com_foto


@app.route("/admin/ponto/<int:registro_id>/foto")
@login_required
@rh_required
def admin_foto_ponto(registro_id):
    foto = FotoPonto.query.filter_by(registro_id=registro_id).first_or_404()
    resposta = make_response(foto.dados)
    resposta.headers["Content-Type"] = foto.mime
    resposta.headers["Cache-Control"] = "private, no-store"
    return resposta


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 1234))
    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
