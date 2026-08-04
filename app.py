import csv
from collections import defaultdict
from datetime import datetime, timedelta
import io
import os
from flask import Flask, render_template, request, redirect, url_for, send_file, flash

# Bibliotecas para o PDF
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Spacer, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)
app.secret_key = "chave_secreta_para_mensagens"

CONTROLE_PONTO = "registro_ponto.csv"
CARGA_HORARIA_DIARIA = timedelta(hours=8)


def make_csv_if_not_exists():
    if not os.path.exists(CONTROLE_PONTO):
        with open(CONTROLE_PONTO, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Data", "Tipo de Registro", "Hora"])


def obter_pontos_hoje():
    if not os.path.exists(CONTROLE_PONTO):
        return []

    data_hoje = datetime.now().strftime("%d/%m/%Y")
    pontos_hoje = []

    with open(CONTROLE_PONTO, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        next(reader, None)
        for linha in reader:
            if len(linha) >= 3 and linha[0] == data_hoje:
                pontos_hoje.append(linha[1])

    return pontos_hoje


def obter_ultimo_ponto():
    if not os.path.exists(CONTROLE_PONTO):
        return "Nenhum ponto registrado hoje"

    with open(CONTROLE_PONTO, mode="r", encoding="utf-8") as file:
        reader = list(csv.reader(file))
        if len(reader) <= 1:
            return "Nenhum ponto registrado"

        ultima_linha = reader[-1]
        return f"{ultima_linha[1]} às {ultima_linha[2]} ({ultima_linha[0]})"


def processar_dados_ponto():
    if not os.path.exists(CONTROLE_PONTO):
        return None, None

    dias = defaultdict(dict)
    with open(CONTROLE_PONTO, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        next(reader, None)
        for linha in reader:
            if len(linha) >= 3:
                data, tipo, hora = linha[0], linha[1], linha[2]
                dias[data][tipo] = hora

    if not dias:
        return None, None

    tabela_linhas = [["Dia", "Entrada", "Almoço", "Retorno", "Saída", "Total Horas"]]
    total_segundos_trabalhados = 0
    total_segundos_extras = 0
    FMT = "%H:%M:%S"

    for dia, registros in dias.items():
        e_str = registros.get("Entrada", "--:--")
        a_str = registros.get("Almoço", "--:--")
        r_str = registros.get("Retorno", "--:--")
        s_str = registros.get("Saída", "--:--")

        tempo_trabalhado = timedelta()

        if e_str != "--:--" and a_str != "--:--":
            t1, t2 = datetime.strptime(e_str, FMT), datetime.strptime(a_str, FMT)
            if t2 > t1:
                tempo_trabalhado += (t2 - t1)

        if r_str != "--:--" and s_str != "--:--":
            t3, t4 = datetime.strptime(r_str, FMT), datetime.strptime(s_str, FMT)
            if t4 > t3:
                tempo_trabalhado += (t4 - t3)

        total_seg = int(tempo_trabalhado.total_seconds())
        total_segundos_trabalhados += total_seg

        if tempo_trabalhado > CARGA_HORARIA_DIARIA:
            extra = tempo_trabalhado - CARGA_HORARIA_DIARIA
            total_segundos_extras += int(extra.total_seconds())

        hrs, mins = divmod(total_seg // 60, 60)
        tabela_linhas.append([dia, e_str, a_str, r_str, s_str, f"{hrs:02d}:{mins:02d}h"])

    hrs_t, mins_t = divmod(total_segundos_trabalhados // 60, 60)
    hrs_e, mins_e = divmod(total_segundos_extras // 60, 60)

    resumo = {
        "total_trabalhado": f"{hrs_t:02d}:{mins_t:02d}h",
        "total_extras": f"{hrs_e:02d}:{mins_e:02d}h",
    }

    return tabela_linhas, resumo


# --- ROTAS DA APLICAÇÃO WEB ---

@app.route("/")
def index():
    make_csv_if_not_exists()
    pontos_batidos = obter_pontos_hoje()
    ultimo_ponto = obter_ultimo_ponto()
    return render_template("index.html", pontos_batidos=pontos_batidos, ultimo_ponto=ultimo_ponto)


@app.route("/registrar/<tipo>", methods=["POST"])
def registrar(tipo):
    make_csv_if_not_exists()
    agora = datetime.now()
    data_atual = agora.strftime("%d/%m/%Y")
    hora_atual = agora.strftime("%H:%M:%S")

    with open(CONTROLE_PONTO, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([data_atual, tipo, hora_atual])

    flash(f"Ponto ({tipo}) registrado às {hora_atual} com sucesso!")
    return redirect(url_for("index"))


@app.route("/exportar-pdf")
def exportar_pdf():
    tabela_dados, resumo = processar_dados_ponto()

    if not tabela_dados or len(tabela_dados) <= 1:
        flash("Nenhum registro encontrado para exportar.")
        return redirect(url_for("index"))

    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elementos = []
    estilos = getSampleStyleSheet()

    titulo_estilo = ParagraphStyle("T", parent=estilos["Heading1"], fontSize=18, alignment=1, spaceAfter=15)
    elementos.append(Paragraph("<b>Relatório de Folha de Ponto</b>", titulo_estilo))
    elementos.append(Paragraph(f"<b>Emissão:</b> {datetime.now().strftime('%d/%m/%Y às %H:%M')}", estilos["Normal"]))
    elementos.append(Spacer(1, 15))

    tabela = Table(tabela_dados, colWidths=[80, 85, 85, 85, 85, 90])
    tabela.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]))
    elementos.append(tabela)
    elementos.append(Spacer(1, 20))

    dados_resumo = [
        ["Horas Totais Trabalhadas:", resumo["total_trabalhado"]],
        ["Total de Horas Extras (Excedente 8h/dia):", resumo["total_extras"]],
    ]
    tabela_resumo = Table(dados_resumo, colWidths=[300, 210])
    tabela_resumo.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#2e7d32")),
    ]))
    elementos.append(tabela_resumo)

    pdf.build(elementos)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Folha_de_Ponto_{datetime.now().strftime('%m_%Y')}.pdf",
        mimetype="application/pdf",
    )


if __name__ == "__main__":
    app.run(debug=True)