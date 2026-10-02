"""
Testes de integração das rotas de folha de ponto.

Cobre:
  - exportação do colaborador (/exportar-ponto) com data_inicio/data_fim
  - exportação do admin (/admin/exportar-ponto/<id>) com a mesma lógica
  - período padrão = primeiro dia do mês corrente até hoje
  - datas futuras nunca são contadas como FALTA
  - PJ não acumula horas faltantes
  - normalização de período (invertido, inválido) e integração com as telas
"""
import csv
import io
import os
import re
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from werkzeug.security import generate_password_hash

TZ = ZoneInfo("America/Sao_Paulo")


class RelatorioPontoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix="ponto-relatorio-test-")
        db_path = Path(cls.tempdir.name) / "test.db"
        upload_path = Path(cls.tempdir.name) / "uploads"
        os.environ.update({
            "TESTING": "true",
            "APP_ENV": "test",
            "AUTO_INIT_DB": "false",
            "PUBLIC_BASE_URL": "http://testserver",
            "TRUSTED_HOSTS": "testserver,localhost",
            "COOKIE_SECURE": "false",
            "DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "SECRET_KEY": "test-secret-only-12345678901234567890",
            "UPLOAD_DIR": str(upload_path),
            "RATE_LIMIT_ENABLED": "false",
        })
        sys.modules.pop("app", None)
        import app as application
        cls.module = application
        cls.app = application.app
        cls.app.config["TESTING"] = True
        cls.app.config["RATE_LIMIT_ENABLED"] = False
        with cls.app.app_context():
            cls.module.db.create_all()

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            cls.module.db.session.remove()
            cls.module.db.engine.dispose()
        try:
            cls.tempdir.cleanup()
        except Exception:
            pass

    def setUp(self):
        with self.app.app_context():
            self.module.db.drop_all()
            self.module.db.create_all()
            self.module._RATE_BUCKETS.clear()
            self.module._NOTIF_CACHE.clear()
            self.module._FERIADOS_CACHE.clear()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def make_user(self, email="user@example.com", admin=False, tipo_contrato="CLT"):
        with self.app.app_context():
            user = self.module.Usuario(
                nome="Usuário <Teste>",
                email=email,
                senha_hash=generate_password_hash("Abcdef1@", method="scrypt"),
                email_confirmado=True,
                is_admin=admin,
                tipo_contrato=tipo_contrato,
                auth_version=0,
            )
            self.module.db.session.add(user)
            self.module.db.session.commit()
            return user.id

    def add_registro(self, user_id, data, tipo, hora):
        with self.app.app_context():
            self.module.db.session.add(self.module.RegistroPonto(
                data=data, tipo=tipo, hora=hora, usuario_id=user_id
            ))
            self.module.db.session.commit()

    def csrf(self, client, path="/login"):
        html = client.get(path).get_data(as_text=True)
        match = re.search(r'name="_csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match, f"CSRF token missing from {path}")
        return match.group(1)

    def login(self, client, email="user@example.com"):
        token = self.csrf(client)
        response = client.post("/login", data={
            "_csrf_token": token, "email": email, "senha": "Abcdef1@",
        })
        self.assertEqual(response.status_code, 302)

    def csv_rows(self, response):
        # O CSV é gerado com BOM utf-8-sig (compatibilidade com Excel)
        text = response.data.decode("utf-8-sig")
        return list(csv.reader(io.StringIO(text)))

    @staticmethod
    def dia_util_anterior(hoje, dias=3):
        d = hoje - timedelta(days=dias)
        while d.weekday() >= 5:
            d -= timedelta(days=1)
        return d

    # ------------------------------------------------------------------
    # Cálculo do relatório
    # ------------------------------------------------------------------
    def test_periodo_default_e_mes_corrente_ate_hoje(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(user)
        self.assertEqual(dados["data_inicio_obj"], hoje.replace(day=1))
        self.assertEqual(dados["data_fim_obj"], hoje)
        for linha in dados["tabela_linhas"][1:]:
            dt = datetime.strptime(linha[0], "%d/%m/%Y").date()
            self.assertLessEqual(dt, hoje)

    def test_periodo_invertido_e_invalido_sao_normalizados(self):
        user_id = self.make_user()
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            # Início após o fim: a folha encolhe até o próprio fim informado
            dados = self.module._gerar_relatorio_ponto_dados(user, "2026-03-10", "2026-03-01")
            self.assertEqual(dados["data_inicio_obj"], date(2026, 3, 1))
            self.assertEqual(dados["data_fim_obj"], date(2026, 3, 1))

            # Apenas a data final informada, no passado
            dados_fim = self.module._gerar_relatorio_ponto_dados(user, "", "2026-02-10")
            self.assertEqual(dados_fim["data_inicio_obj"], date(2026, 2, 1))
            self.assertEqual(dados_fim["data_fim_obj"], date(2026, 2, 10))

            # Datas inválidas caem no padrão: mês corrente até hoje
            hoje = datetime.now(TZ).date()
            dados_invalido = self.module._gerar_relatorio_ponto_dados(user, "31/02/2026", "abc")
            self.assertEqual(dados_invalido["data_fim_obj"], hoje)
            self.assertEqual(dados_invalido["data_inicio_obj"], hoje.replace(day=1))

    def test_datas_futuras_nao_sao_contadas_como_falta(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        inicio = hoje - timedelta(days=40)
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(
                user, inicio.isoformat(), (hoje + timedelta(days=60)).isoformat()
            )
        for linha in dados["tabela_linhas"][1:]:
            dt = datetime.strptime(linha[0], "%d/%m/%Y").date()
            if dt > hoje:
                self.assertEqual(linha[-1], "-", f"Dia futuro {dt} marcado como {linha[-1]}")
            elif dt == hoje:
                self.assertEqual(linha[-1], "Em Aberto")

        dias_uteis_passados = sum(
            1 for linha in dados["tabela_linhas"][1:]
            if datetime.strptime(linha[0], "%d/%m/%Y").date() < hoje
            and self.module.eh_dia_util(datetime.strptime(linha[0], "%d/%m/%Y").date())
        )
        self.assertEqual(dados["total_faltas_dias"], dias_uteis_passados)

    def test_dia_util_passado_sem_registro_conta_falta(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        inicio = self.dia_util_anterior(hoje, 10)
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(user, inicio.isoformat(), hoje.isoformat())
        linhas = {linha[0]: linha for linha in dados["tabela_linhas"][1:]}
        self.assertEqual(linhas[inicio.strftime("%d/%m/%Y")][-1], "FALTA")
        self.assertGreaterEqual(dados["total_faltas_dias"], 1)
        self.assertGreater(dados["total_segundos_faltantes"], 0)
        self.assertLess(dados["balanco_segundos"], 0)
        self.assertTrue(dados["texto_balanco"].startswith("-"))

    def test_registro_completo_gera_horas_e_nao_conta_falta(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        dia = self.dia_util_anterior(hoje)
        self.add_registro(user_id, dia.strftime("%d/%m/%Y"), "Entrada", "09:00:00")
        self.add_registro(user_id, dia.strftime("%d/%m/%Y"), "Saída", "18:00:00")
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(user, dia.isoformat(), dia.isoformat())
        self.assertEqual(dados["tabela_linhas"][1][1], "09:00")
        self.assertEqual(dados["tabela_linhas"][1][2], "18:00")
        self.assertEqual(dados["tabela_linhas"][1][3], "09:00h")
        self.assertEqual(dados["total_segundos_extras"], 3600)
        self.assertEqual(dados["total_faltas_dias"], 0)
        self.assertEqual(dados["balanco_segundos"], 3600)

    def test_pj_nao_acumula_horas_faltantes(self):
        user_id = self.make_user(email="pj@example.com", tipo_contrato="PJ")
        hoje = datetime.now(TZ).date()
        inicio = self.dia_util_anterior(hoje, 10)
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(user, inicio.isoformat(), hoje.isoformat())
        self.assertTrue(dados["is_pj"])
        self.assertEqual(dados["total_segundos_faltantes"], 0)
        self.assertEqual(dados["total_faltas_dias"], 0)

    def test_colunas_extram_para_multiplos_pares(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        dia = self.dia_util_anterior(hoje)
        for tipo, hora in (("Entrada", "08:00:00"), ("Saída", "12:00:00"),
                           ("Entrada", "13:00:00"), ("Saída", "19:00:00")):
            self.add_registro(user_id, dia.strftime("%d/%m/%Y"), tipo, hora)
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(user, dia.isoformat(), dia.isoformat())
        self.assertEqual(dados["max_pares"], 2)
        self.assertEqual(
            dados["tabela_linhas"][0],
            ["Dia", "Entrada 1", "Saída 1", "Entrada 2", "Saída 2", "Total / Status"],
        )
        self.assertEqual(
            dados["tabela_linhas"][1],
            [dia.strftime("%d/%m/%Y"), "08:00", "12:00", "13:00", "19:00", "10:00h"],
        )

    def test_registro_fora_do_periodo_e_ignorado(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        dentro = self.dia_util_anterior(hoje, 5)
        fora = dentro - timedelta(days=10)
        for dia in (dentro, fora):
            self.add_registro(user_id, dia.strftime("%d/%m/%Y"), "Entrada", "09:00:00")
            self.add_registro(user_id, dia.strftime("%d/%m/%Y"), "Saída", "18:00:00")
        with self.app.app_context():
            user = self.module.Usuario.query.get(user_id)
            dados = self.module._gerar_relatorio_ponto_dados(user, dentro.isoformat(), dentro.isoformat())
        self.assertEqual(len(dados["tabela_linhas"]), 2)
        self.assertEqual(dados["tabela_linhas"][1][1], "09:00")
        self.assertEqual(dados["total_segundos_trabalhados"], 9 * 3600)

    # ------------------------------------------------------------------
    # Rotas HTTP
    # ------------------------------------------------------------------
    def test_rota_employee_exporta_todos_os_formatos_com_periodo(self):
        user_id = self.make_user()
        hoje = datetime.now(TZ).date()
        dia = self.dia_util_anterior(hoje)
        self.add_registro(user_id, dia.strftime("%d/%m/%Y"), "Entrada", "09:00:00")
        self.add_registro(user_id, dia.strftime("%d/%m/%Y"), "Saída", "18:00:00")
        inicio = hoje - timedelta(days=40)
        query = f"data_inicio={inicio.isoformat()}&data_fim={hoje.isoformat()}"

        with self.app.test_client() as client:
            self.login(client)

            pdf = client.get(f"/exportar-ponto?format=pdf&{query}")
            self.assertEqual(pdf.status_code, 200)
            self.assertTrue(pdf.data.startswith(b"%PDF"))

            csv_resp = client.get(f"/exportar-ponto?format=csv&{query}")
            self.assertEqual(csv_resp.status_code, 200)
            self.assertIn("text/csv", csv_resp.content_type)
            rows = self.csv_rows(csv_resp)
            self.assertEqual(rows[0][0], "Dia")
            self.assertIn(dia.strftime("%d/%m/%Y"), [r[0] for r in rows[1:]])
            self.assertIn("FALTA", [r[-1] for r in rows[1:]])

            excel = client.get(f"/exportar-ponto?format=excel&{query}")
            self.assertEqual(excel.status_code, 200)
            self.assertTrue(excel.data.startswith(b"PK"))

    def test_rota_employee_formato_invalido_redireciona(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            response = client.get("/exportar-ponto?format=docx")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/meu_historico")

    def test_export_sem_registros_ainda_gera_arquivo(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            response = client.get("/exportar-ponto?format=csv")
            self.assertEqual(response.status_code, 200)
            rows = self.csv_rows(response)
            self.assertEqual(rows[0][0], "Dia")
            self.assertGreater(len(rows), 1)

    def test_export_exige_login(self):
        self.make_user()
        with self.app.test_client() as client:
            self.assertEqual(client.get("/exportar-ponto?format=pdf").status_code, 302)
            self.assertEqual(client.get("/admin/exportar-ponto/1?format=pdf").status_code, 302)

    def test_rota_admin_exporta_periodo_do_usuario_selecionado(self):
        self.make_user(email="admin@example.com", admin=True)
        alvo_id = self.make_user(email="alvo@example.com")
        hoje = datetime.now(TZ).date()
        dia = self.dia_util_anterior(hoje)
        self.add_registro(alvo_id, dia.strftime("%d/%m/%Y"), "Entrada", "08:00:00")
        self.add_registro(alvo_id, dia.strftime("%d/%m/%Y"), "Saída", "17:00:00")

        with self.app.test_client() as client:
            self.login(client, "admin@example.com")
            url = f"/admin/exportar-ponto/{alvo_id}?format=csv&data_inicio={dia.isoformat()}&data_fim={dia.isoformat()}"
            response = client.get(url)
            self.assertEqual(response.status_code, 200)
            rows = self.csv_rows(response)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1][0], dia.strftime("%d/%m/%Y"))
            self.assertEqual(rows[1][-1], "09:00h")  # 08:00 -> 17:00

            pdf = client.get(url.replace("format=csv", "format=pdf"))
            self.assertEqual(pdf.status_code, 200)
            self.assertTrue(pdf.data.startswith(b"%PDF"))

    def test_rota_admin_nega_usuario_nao_admin(self):
        self.make_user(email="comum@example.com")
        alvo_id = self.make_user(email="alvo@example.com")
        with self.app.test_client() as client:
            self.login(client, "comum@example.com")
            response = client.get(f"/admin/exportar-ponto/{alvo_id}?format=csv")
            self.assertIn(response.status_code, (302, 403, 404))

    def test_rota_admin_usuario_inexistente_retorna_404(self):
        self.make_user(email="admin2@example.com", admin=True)
        with self.app.test_client() as client:
            self.login(client, "admin2@example.com")
            self.assertEqual(client.get("/admin/exportar-ponto/999999?format=csv").status_code, 404)

    # ------------------------------------------------------------------
    # Integração com as telas
    # ------------------------------------------------------------------
    def test_meu_historico_renderiza_periodo_resolvido_nos_links(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            html = client.get("/meu_historico").get_data(as_text=True)
            hoje = datetime.now(TZ).date()
            self.assertIn(f'value="{hoje.replace(day=1).isoformat()}"', html)
            self.assertIn(f'value="{hoje.isoformat()}"', html)
            for fmt in ("pdf", "excel", "csv"):
                self.assertIn(f"/exportar-ponto?format={fmt}", html)
                self.assertIn("data_inicio=" + hoje.replace(day=1).isoformat(), html)
                self.assertIn("data_fim=" + hoje.isoformat(), html)

    def test_meu_historico_mantem_periodo_escolhido(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            html = client.get("/meu_historico?data_inicio=2026-02-01&data_fim=2026-02-10").get_data(as_text=True)
            self.assertIn('value="2026-02-01"', html)
            self.assertIn('value="2026-02-10"', html)

    def test_meu_historico_data_fim_no_passado_usa_primeiro_dia_do_mes(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            html = client.get("/meu_historico?data_fim=2026-02-10").get_data(as_text=True)
            self.assertIn('value="2026-02-01"', html)
            self.assertIn('value="2026-02-10"', html)

    def test_meu_historico_expoe_atalhos_de_periodo(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            html = client.get("/meu_historico").get_data(as_text=True)
            self.assertIn('id="formMeuHistorico"', html)
            self.assertIn('data-periodo-preset="current_month"', html)
            self.assertIn('data-periodo-preset="prev_month"', html)
            self.assertIn('data-periodo-preset="last_30"', html)

    def test_admin_fragmento_historico_usa_periodo_no_dropdown(self):
        self.make_user(email="admin3@example.com", admin=True)
        alvo_id = self.make_user(email="alvo3@example.com")
        with self.app.test_client() as client:
            self.login(client, "admin3@example.com")
            html = client.get(
                f"/admin/fragment/historico?usuario_id={alvo_id}&data_inicio=2026-02-01&data_fim=2026-02-10"
            ).get_data(as_text=True)
            self.assertIn("data_inicio=2026-02-01", html)
            self.assertIn("data_fim=2026-02-10", html)
            for fmt in ("pdf", "excel", "csv"):
                self.assertIn(f"/admin/exportar-ponto/{alvo_id}?format={fmt}", html)

    def test_admin_fragmento_historico_sem_usuario_mostra_modal(self):
        self.make_user(email="admin4@example.com", admin=True)
        self.make_user(email="alvo4@example.com")
        with self.app.test_client() as client:
            self.login(client, "admin4@example.com")
            html = client.get("/admin/fragment/historico").get_data(as_text=True)
            self.assertIn('data-bs-target="#modalExportarPonto"', html)
            self.assertNotIn("/admin/exportar-ponto/", html)

    def test_admin_fragmento_usuarios_tem_botao_folha_sem_js_inline(self):
        self.make_user(email="admin5@example.com", admin=True)
        alvo_id = self.make_user(email="alvo5@example.com")
        with self.app.test_client() as client:
            self.login(client, "admin5@example.com")
            html = client.get("/admin/fragment/usuarios").get_data(as_text=True)
            self.assertIn("btn-emitir-folha", html)
            self.assertIn(f'data-user-id="{alvo_id}"', html)
            self.assertNotIn("openExportModalForUser(", html)
            self.assertIn("Usuário &lt;Teste&gt;", html)

    def test_admin_shell_expoe_modal_e_delegacao_do_botao_folha(self):
        self.make_user(email="admin6@example.com", admin=True)
        with self.app.test_client() as client:
            self.login(client, "admin6@example.com")
            html = client.get("/admin/usuarios").get_data(as_text=True)
            self.assertIn('id="modalExportarPonto"', html)
            self.assertIn("window.openExportModalForUser", html)
            self.assertIn("btn-emitir-folha", html)
            self.assertIn("setExportPeriodPreset", html)
            self.assertIn("Mês Atual", html)
            self.assertIn("Mês Anterior", html)
            self.assertIn("Últimos 30 Dias", html)


if __name__ == "__main__":
    unittest.main()
