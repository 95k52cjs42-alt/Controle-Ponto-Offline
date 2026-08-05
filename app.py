from collections import defaultdict
from datetime import datetime, timedelta
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
app.secret_key = "chave_secreta_super_segura_ponto_web"

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://postgres:Smartpixel2026@db.qptqynskpqabslxjedtf.supabase.co:5432/postgres"
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
  pontos = db.relationship("RegistroPonto", backref="usuario", lazy=True)


class RegistroPonto(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  data = db.Column(db.String(10), nullable=False)  # DD/MM/YYYY
  tipo = db.Column(
      db.String(20), nullable=False
  )
  hora = db.Column(db.String(8), nullable=False)  # HH:MM:SS
  usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
  return Usuario.query.get(int(user_id))


with app.app_context():
  db.create_all()


# ==========================================
# ROTAS DE AUTENTICAÇÃO (LOGIN, CADASTRO, LOGOUT)
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
      flash("Este e-mail já está cadastrado. Faça login ou use outro e-mail.")
      return redirect(url_for("cadastro"))

    novo_usuario = Usuario(
        nome=nome,
        email=email,
        senha_hash=generate_password_hash(senha, method="scrypt"),
    )
    db.session.add(novo_usuario)
    db.session.commit()

    flash("Conta criada com sucesso! Faça seu login para acessar.")
    return redirect(url_for("login"))

  return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
  logout_user()
  flash("Você saiu da conta.")
  return redirect(url_for("login"))


# ==========================================
#              ROTAS DO PONTO 
# ==========================================
@app.route("/")
@login_required
def index():
  data_hoje = datetime.now().strftime("%d/%m/%Y")

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
  agora = datetime.now()
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
        tempo_trabalhado += t3 - t4 if t4 < t3 else t4 - t3

    tot = int(tempo_trabalhado.total_seconds())
    total_segundos_trabalhados += tot

    if tempo_trabalhado > CARGA_HORARIA_DIARIA:
      extra = tempo_trabalhado - CARGA_HORARIA_DIARIA
      total_segundos_extras += int(extra.total_seconds())

    hrs, mins = divmod(tot // 60, 60)
    tabela_linhas.append([dia, e, a, r, s, f"{hrs:02d}:{mins:02d}h"])

  hrs_t, mins_t = divmod(total_segundos_trabalhados // 60, 60)
  hrs_e, mins_e = divmod(total_segundos_extras // 60, 60)

# ==========================================
#       Configura o PDF do reportlab
#=========================================

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
          f" {datetime.now().strftime('%d/%m/%Y às %H:%M')}",
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

  nome_arquivo_pdf = (
      f"Folha_Ponto_{current_user.nome.replace(' ', '_')}_{datetime.now().strftime('%m_%Y')}.pdf"
  )

  return send_file(
      buffer,
      as_attachment=True,
      download_name=nome_arquivo_pdf,
      mimetype="application/pdf",
  )


if __name__ == "__main__":
  app.run(debug=True)