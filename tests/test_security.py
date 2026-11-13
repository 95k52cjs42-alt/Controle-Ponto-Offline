import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from werkzeug.security import generate_password_hash


class SecurityRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix="ponto-security-test-")
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
            # O SQLite ignora chaves estrangeiras por padrão; liga para o
            # comportamento ficar igual ao do PostgreSQL (Supabase).
            from sqlalchemy import event

            @event.listens_for(cls.module.db.engine, "connect")
            def _sqlite_fk_on(dbapi_conn, _record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

            cls.module.db.engine.dispose()
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

    def make_user(self, email="user@example.com", admin=False, needs_reset=False, rh=None, ti=None):
        # admin=True equivale a RH + TI; rh/ti permitem papéis isolados.
        rh = admin if rh is None else rh
        ti = admin if ti is None else ti
        with self.app.app_context():
            user = self.module.Usuario(
                nome="Usuário <Teste>",
                email=email,
                senha_hash=generate_password_hash("Abcdef1@", method="scrypt"),
                email_confirmado=True,
                is_rh=rh,
                is_ti=ti,
                precisa_redefinir_senha=needs_reset,
                auth_version=0,
            )
            self.module.db.session.add(user)
            self.module.db.session.commit()
            return user.id

    def csrf(self, client, path="/login"):
        html = client.get(path).get_data(as_text=True)
        match = re.search(r'name="_csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match, f"CSRF token missing from {path}")
        return match.group(1)

    def login(self, client, email="user@example.com"):
        token = self.csrf(client)
        response = client.post("/login", data={
            "_csrf_token": token,
            "email": email,
            "senha": "Abcdef1@",
        })
        self.assertEqual(response.status_code, 302)

    def test_csrf_and_post_logout(self):
        self.make_user()
        with self.app.test_client() as client:
            response = client.post("/login", data={"email": "user@example.com", "senha": "Abcdef1@"})
            self.assertEqual(response.status_code, 403)
            self.login(client)
            token = self.csrf(client, "/")
            self.assertEqual(client.get("/logout").status_code, 405)
            response = client.post("/logout", data={"_csrf_token": token})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/login")
            self.assertEqual(client.get("/").status_code, 302)

    def test_token_is_purpose_bound_hashed_and_single_use(self):
        self.make_user()
        with self.app.app_context():
            user = self.module.Usuario.query.filter_by(email="user@example.com").first()
            raw, row = self.module.issue_security_token(
                user.id, self.module.SecurityToken.PURPOSE_RESET, 1800
            )
            self.assertNotIn(raw, row.token_hash)
            self.assertIsNotNone(self.module.peek_security_token(raw, self.module.SecurityToken.PURPOSE_RESET))
            self.assertIsNone(self.module.peek_security_token(raw, self.module.SecurityToken.PURPOSE_INVITE))
            self.assertIsNotNone(self.module.consume_security_token(raw, self.module.SecurityToken.PURPOSE_RESET))
            self.assertIsNone(self.module.consume_security_token(raw, self.module.SecurityToken.PURPOSE_RESET))

    def test_auth_version_revokes_existing_session(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            self.assertEqual(client.get("/").status_code, 200)
            with self.app.app_context():
                user = self.module.Usuario.query.filter_by(email="user@example.com").first()
                self.module.revoke_user_sessions(user)
            self.assertEqual(client.get("/").status_code, 302)
    def test_autocadastro_publico_fechado(self):
        with self.app.test_client() as client:
            response = client.get("/cadastro")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/login")
            token = self.csrf(client, "/login")
            response = client.post("/cadastro", data={
                "_csrf_token": token,
                "nome": "Intruso",
                "email": "intruso@example.com",
                "senha": "Abcdef1@",
            })
            self.assertEqual(response.status_code, 302)
            html = client.get("/login").get_data(as_text=True)
            self.assertIn("administrador da empresa", html)
            self.assertNotIn('href="/cadastro"', html)
        with self.app.app_context():
            self.assertEqual(self.module.Usuario.query.count(), 0)

    def test_link_de_confirmacao_antigo_nao_cria_conta(self):
        with self.app.app_context():
            m = self.module
            # Token emitido antes de o autocadastro ser fechado.
            raw = "x" * 64
            m.db.session.add(m.SecurityToken(
                email="confirm@example.com", nome="Confirmado",
                senha_hash=generate_password_hash("Abcdef1@", method="scrypt"),
                purpose=m.SecurityToken.PURPOSE_CONFIRM, token_hash=m._token_digest(raw),
                expira_em=m._local_now() + m.timedelta(hours=1),
            ))
            m.db.session.commit()
            with self.assertRaises(ValueError):
                m.issue_security_token(None, m.SecurityToken.PURPOSE_CONFIRM, 1800, email="novo@example.com")
        with self.app.test_client() as client:
            self.assertEqual(client.get(f"/confirm_email/{raw}").location, "/login")
            token = self.csrf(client, "/login")
            response = client.post(f"/confirm_email/{raw}", data={"_csrf_token": token})
            self.assertEqual(response.location, "/login")
        with self.app.app_context():
            self.assertEqual(self.module.Usuario.query.count(), 0)

    def test_host_rejection_and_fixed_email_link(self):
        self.make_user()
        with self.app.test_client() as client:
            self.assertEqual(client.get("/login", headers={"Host": "evil.example"}).status_code, 400)
            token = self.csrf(client, "/forgot_password")
            with patch.object(self.module, "_send_email", return_value=True) as send:
                response = client.post("/forgot_password", data={
                    "_csrf_token": token,
                    "email": "user@example.com",
                })
            self.assertEqual(response.status_code, 200)
            body = send.call_args.args[2]
            self.assertIn("http://testserver/reset_password/", body)
            self.assertNotIn("evil.example", body)

    def test_profile_image_content_and_size_validation(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            token = self.csrf(client, "/")
            valid = io.BytesIO()
            Image.new("RGB", (2, 2), "red").save(valid, format="PNG")
            valid.seek(0)
            response = client.post("/perfil/upload-foto", data={
                "_csrf_token": token,
                "foto": (valid, "avatar.png"),
            }, content_type="multipart/form-data")
            self.assertEqual(response.status_code, 302)
            with self.app.app_context():
                self.assertTrue(self.module.Usuario.query.filter_by(email="user@example.com").first().foto_url)
            token = self.csrf(client, "/")
            fake = io.BytesIO(b"not an image")
            client.post("/perfil/upload-foto", data={
                "_csrf_token": token,
                "foto": (fake, "avatar.png"),
            }, content_type="multipart/form-data")
            with self.app.app_context():
                self.assertTrue(self.module.Usuario.query.filter_by(email="user@example.com").first().foto_url)

    def test_uploaded_profile_image_access_control_and_traversal(self):
        user_id = self.make_user()
        with self.app.test_client() as client:
            unauth_resp = client.get("/uploads/perfil/user_1_0123456789abcdef01234567.png")
            self.assertEqual(unauth_resp.status_code, 302)

            self.login(client)

            self.assertEqual(client.get("/uploads/perfil/evil.png").status_code, 404)
            self.assertEqual(client.get("/uploads/perfil/../app.py").status_code, 404)
            self.assertEqual(client.get("/uploads/perfil/user_1_invalidformat.png").status_code, 404)
            self.assertEqual(client.get("/uploads/perfil/user_1_0123456789abcdef01234567.sh").status_code, 404)

            token = self.csrf(client, "/")
            valid = io.BytesIO()
            Image.new("RGB", (4, 4), "blue").save(valid, format="PNG")
            valid.seek(0)
            upload_resp = client.post("/perfil/upload-foto", data={
                "_csrf_token": token,
                "foto": (valid, "avatar.png"),
            }, content_type="multipart/form-data")
            self.assertEqual(upload_resp.status_code, 302)

            with self.app.app_context():
                user = self.module.db.session.get(self.module.Usuario, user_id)
                foto_url = user.foto_url
                self.assertIsNotNone(foto_url)
                self.assertTrue(foto_url.startswith("/uploads/perfil/user_"))

            file_resp = client.get(foto_url)
            self.assertEqual(file_resp.status_code, 200)
            self.assertIn("image", file_resp.content_type)
            file_resp.close()

    def test_safe_reportlab_image_path_validation(self):
        upload_folder = Path(self.app.config["UPLOAD_FOLDER"])
        upload_folder.mkdir(parents=True, exist_ok=True)
        test_file = upload_folder / "test_image.png"
        test_file.write_bytes(b"dummy image data")

        self.assertEqual(
            self.module._safe_reportlab_image_path(str(test_file)),
            os.path.realpath(str(test_file)),
        )
        self.assertIsNone(self.module._safe_reportlab_image_path(str(Path(__file__).resolve())))
        self.assertIsNone(self.module._safe_reportlab_image_path(str(upload_folder / ".." / "test.db")))
        self.assertIsNone(self.module._safe_reportlab_image_path(str(upload_folder / "nonexistent.png")))
        self.assertIsNone(self.module._safe_reportlab_image_path("https://evil.example/pic.png"))
        self.assertIsNone(self.module._safe_reportlab_image_path(None))
        self.assertIsNone(self.module._safe_reportlab_image_path(123))

    def test_email_html_escaping(self):
        admin_id = self.make_user(email="admin@example.com", admin=True)
        with self.app.test_client() as client:
            self.login(client, "admin@example.com")
            token = self.csrf(client, "/admin")
            with patch.object(self.module, "_send_email", return_value=True) as mock_send:
                response = client.post("/admin/cadastrar_usuario", data={
                    "_csrf_token": token,
                    "nome": "New <img src=x onerror=alert(1)>",
                    "email": "newuser@example.com",
                    "tipo_contrato": "CLT",
                    "modo_acesso": "convite",
                })
                self.assertEqual(response.status_code, 302)
                mock_send.assert_called_once()
                body = mock_send.call_args[0][2]
                self.assertNotIn("<img", body)
                self.assertIn("&lt;img src=x onerror=alert(1)&gt;", body)

        with self.app.test_client() as client:
            token = self.csrf(client, "/forgot_password")
            with patch.object(self.module, "_send_email", return_value=True) as mock_send:
                response = client.post("/forgot_password", data={
                    "_csrf_token": token,
                    "email": "newuser@example.com",
                })
                self.assertEqual(response.status_code, 200)
                mock_send.assert_called_once()
                body = mock_send.call_args[0][2]
                self.assertNotIn("<img", body)
                self.assertIn("&lt;img src=x onerror=alert(1)&gt;", body)

    def test_formula_neutralisation_pdf_escape_and_headers(self):
        self.assertEqual(
            self.module._safe_export_rows([
                ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tTAB", "\rCR", "\nLF", " space", "ok", None, 123]
            ]),
            [
                ["'=1+1", "'+cmd", "'-2", "'@SUM(A1)", "'\tTAB", "'\rCR", "'\nLF", "' space", "ok", "", "123"]
            ],
        )
        self.make_user(email="pdf@example.com")
        with self.app.test_client() as client:
            self.login(client, "pdf@example.com")
            response_pdf = client.get("/exportar-ponto?format=pdf")
            self.assertEqual(response_pdf.status_code, 200)
            self.assertTrue(response_pdf.data.startswith(b"%PDF"))
            self.assertEqual(response_pdf.headers["Content-Disposition"], "attachment; filename=Folha_Ponto.pdf")
            self.assertEqual(response_pdf.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response_pdf.headers["X-Frame-Options"], "DENY")

            response_csv = client.get("/exportar-ponto?format=csv")
            self.assertEqual(response_csv.status_code, 200)
            self.assertIn("text/csv", response_csv.content_type)
            self.assertEqual(response_csv.headers["Content-Disposition"], "attachment; filename=Folha_Ponto.csv")

            response_excel = client.get("/exportar-ponto?format=excel")
            self.assertEqual(response_excel.status_code, 200)
            self.assertEqual(
                response_excel.content_type,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            self.assertEqual(response_excel.headers["Content-Disposition"], "attachment; filename=Folha_Ponto.xlsx")

    def test_external_referrer_is_not_a_redirect_target(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            token = self.csrf(client, "/")
            response = client.post("/alterar_senha", data={
                "_csrf_token": token,
                "senha_atual": "wrong",
                "nova_senha": "Abcdef1@",
                "confirmar_senha": "Abcdef1@",
            }, headers={"Referer": "https://evil.example/admin"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/")

            token = self.csrf(client, "/")
            response = client.post("/alterar_senha", data={
                "_csrf_token": token,
                "senha_atual": "wrong",
                "nova_senha": "Abcdef1@",
                "confirmar_senha": "Abcdef1@",
            }, headers={"Referer": "http://testserver/perfil"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/perfil")

    def test_admin_can_delete_user_with_audit_logs(self):
        self.make_user(email="admin@example.com", admin=True)
        alvo_id = self.make_user(email="alvo@example.com")
        with self.app.app_context():
            m = self.module
            m.db.session.add(m.RegistroPonto(data="10/11/2026", tipo="Entrada", hora="08:00:00", usuario_id=alvo_id))
            m.db.session.add(m.SolicitacaoCorrecao(
                data_ponto="10/11/2026", tipo_ponto="Saída", hora_correta="17:00:00",
                justificativa="esqueci", usuario_id=alvo_id,
            ))
            m.db.session.add(m.Notificacao(usuario_id=alvo_id, mensagem="oi"))
            m.db.session.commit()
            m.registrar_log(alvo_id, "Alterou a própria senha")

        with self.app.test_client() as client:
            self.login(client, email="admin@example.com")
            token = self.csrf(client, "/")
            response = client.post(f"/admin/excluir-usuario/{alvo_id}", data={"_csrf_token": token})
            self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            m = self.module
            self.assertIsNone(m.db.session.get(m.Usuario, alvo_id))
            self.assertEqual(m.RegistroPonto.query.filter_by(usuario_id=alvo_id).count(), 0)
            # O log de auditoria do usuário excluído é preservado com o nome.
            log = m.LogAuditoria.query.filter_by(acao="Alterou a própria senha").one()
            self.assertIsNone(log.usuario_id)
            self.assertEqual(log.usuario_nome, "Usuário <Teste>")
            self.assertTrue(m.LogAuditoria.query.filter(
                m.LogAuditoria.acao.like("Excluiu usuário%")
            ).count() == 1)

        with self.app.test_client() as client:
            self.login(client, email="admin@example.com")
            html = client.get("/admin/fragment/logs").get_data(as_text=True)
            self.assertIn("Usuário &lt;Teste&gt;", html)

    def _login_senha(self, client, email, senha):
        token = self.csrf(client)
        return client.post("/login", data={"_csrf_token": token, "email": email, "senha": senha})

    def test_admin_cadastra_usuario_com_senha(self):
        self.make_user(email="admin@example.com", admin=True)
        with self.app.app_context():
            dep = self.module.Departamento(nome="TI")
            self.module.db.session.add(dep)
            self.module.db.session.commit()
            dep_id = dep.id

        with self.app.test_client() as client:
            self.login(client, email="admin@example.com")
            token = self.csrf(client, "/admin")
            base = {"_csrf_token": token, "nome": "Novo", "tipo_contrato": "PJ", "modo_acesso": "senha"}
            with patch.object(self.module, "_send_email", return_value=True) as mock_send:
                # Senha fora da política e confirmação divergente são recusadas.
                client.post("/admin/cadastrar_usuario", data={**base, "email": "fraca@example.com",
                            "senha": "abc", "confirmar_senha": "abc"})
                client.post("/admin/cadastrar_usuario", data={**base, "email": "diverge@example.com",
                            "senha": "Senha@123", "confirmar_senha": "Senha@124"})
                response = client.post("/admin/cadastrar_usuario", data={
                    **base, "email": "Novo@Example.com", "senha": "Senha@123",
                    "confirmar_senha": "Senha@123", "exigir_troca": "on", "departamento_id": str(dep_id),
                })
                self.assertEqual(response.status_code, 302)
                # Mesmo e-mail com outra caixa é duplicado.
                client.post("/admin/cadastrar_usuario", data={**base, "email": "novo@example.com",
                            "senha": "Senha@123", "confirmar_senha": "Senha@123"})
                mock_send.assert_not_called()

        with self.app.app_context():
            m = self.module
            self.assertIsNone(m.Usuario.query.filter_by(email="fraca@example.com").first())
            self.assertIsNone(m.Usuario.query.filter_by(email="diverge@example.com").first())
            self.assertEqual(m.Usuario.query.filter(m.db.func.lower(m.Usuario.email) == "novo@example.com").count(), 1)
            novo = m.Usuario.query.filter_by(email="novo@example.com").one()
            self.assertTrue(novo.precisa_redefinir_senha)
            self.assertFalse(novo.tem_gestao)
            self.assertEqual(novo.tipo_contrato, "PJ")
            self.assertEqual(novo.departamento_id, dep_id)
            log = m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Cadastrou usuário Novo%")).one()
            self.assertNotIn("Senha@123", log.acao)

        # O colaborador entra com a senha definida e é levado à troca obrigatória.
        with self.app.test_client() as client:
            response = self._login_senha(client, "novo@example.com", "Senha@123")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/redefinir_senha_forca")

    def test_admin_altera_senha_de_usuario(self):
        self.make_user(email="admin@example.com", admin=True)
        alvo_id = self.make_user(email="alvo@example.com")
        with self.app.app_context():
            m = self.module
            convite, _ = m.issue_security_token(alvo_id, m.SecurityToken.PURPOSE_INVITE, 3600)
            m.db.session.commit()

        alvo = self.app.test_client()
        self.login(alvo, email="alvo@example.com")
        self.assertEqual(alvo.get("/", follow_redirects=False).status_code, 200)

        with self.app.test_client() as client:
            self.login(client, email="admin@example.com")
            token = self.csrf(client, "/admin")
            # Política de senha vale aqui também.
            client.post(f"/admin/usuarios/{alvo_id}/senha", data={
                "_csrf_token": token, "nova_senha": "fraca", "confirmar_senha": "fraca"})
            with self.app.app_context():
                self.assertTrue(self.module.check_password_hash(
                    self.module.db.session.get(self.module.Usuario, alvo_id).senha_hash, "Abcdef1@"))

            response = client.post(f"/admin/usuarios/{alvo_id}/senha", data={
                "_csrf_token": token, "nova_senha": "Nova@Senha9", "confirmar_senha": "Nova@Senha9",
            })
            self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            m = self.module
            user = m.db.session.get(m.Usuario, alvo_id)
            self.assertTrue(m.check_password_hash(user.senha_hash, "Nova@Senha9"))
            self.assertFalse(user.precisa_redefinir_senha)
            # Link de convite pendente deixa de valer.
            self.assertIsNone(m._get_valid_security_token(convite, m.SecurityToken.PURPOSE_INVITE))
            log = m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Alterou a senha do usuário%")).one()
            self.assertEqual(log.entidade_id, alvo_id)
            self.assertNotIn("Nova@Senha9", log.acao)

        # A sessão aberta do colaborador foi encerrada.
        self.assertEqual(alvo.get("/", follow_redirects=False).status_code, 302)
        with self.app.test_client() as client:
            response = self._login_senha(client, "alvo@example.com", "Nova@Senha9")
            self.assertEqual(response.location, "/")

    def test_admin_nao_altera_propria_senha_pela_tela_de_usuarios(self):
        admin_id = self.make_user(email="admin@example.com", admin=True)
        with self.app.test_client() as client:
            self.login(client, email="admin@example.com")
            token = self.csrf(client, "/admin")
            client.post(f"/admin/usuarios/{admin_id}/senha", data={
                "_csrf_token": token, "nova_senha": "Nova@Senha9", "confirmar_senha": "Nova@Senha9"})
        with self.app.app_context():
            m = self.module
            self.assertTrue(m.check_password_hash(m.db.session.get(m.Usuario, admin_id).senha_hash, "Abcdef1@"))

    def test_nao_admin_nao_altera_senha_de_outro(self):
        self.make_user(email="func@example.com")
        outro_id = self.make_user(email="outro@example.com")
        with self.app.test_client() as client:
            self.login(client, email="func@example.com")
            token = self.csrf(client, "/")
            client.post(f"/admin/usuarios/{outro_id}/senha", data={
                "_csrf_token": token, "nova_senha": "Nova@Senha9", "confirmar_senha": "Nova@Senha9"})
            client.post("/admin/cadastrar_usuario", data={
                "_csrf_token": token, "nome": "X", "email": "x@example.com", "modo_acesso": "senha",
                "senha": "Nova@Senha9", "confirmar_senha": "Nova@Senha9"})
        with self.app.app_context():
            m = self.module
            self.assertTrue(m.check_password_hash(m.db.session.get(m.Usuario, outro_id).senha_hash, "Abcdef1@"))
            self.assertIsNone(m.Usuario.query.filter_by(email="x@example.com").first())

    def test_outro_app_flask_no_mesmo_host_nao_derruba_sessao(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            token = self.csrf(client, "/")
            # Outro app Flask em outra porta do localhost grava o cookie padrão.
            client.set_cookie("session", "cookie-de-outro-app", domain="localhost")
            response = client.post("/logout", data={"_csrf_token": token})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/login")

    def test_csrf_invalido_mostra_pagina_amigavel_sem_executar(self):
        self.make_user()
        with self.app.test_client() as client:
            self.login(client)
            response = client.post("/logout", data={"_csrf_token": "token-velho"},
                                   headers={"Referer": "http://testserver/meu_historico"})
            self.assertEqual(response.status_code, 403)
            html = response.get_data(as_text=True)
            self.assertIn("Página desatualizada", html)
            self.assertIn('href="/meu_historico"', html)
            # A ação não foi executada: continua logado.
            self.assertEqual(client.get("/").status_code, 200)
            # Chamadas de API continuam recebendo 403 simples.
            response = client.post("/api/localizacao", json={"uf": "SP"})
            self.assertEqual(response.status_code, 403)
            self.assertNotIn("Página desatualizada", response.get_data(as_text=True))

    # ------------------------------------------------------------------
    # Parâmetros de jornada (TI)
    # ------------------------------------------------------------------
    def _form_jornada(self, token, **extra):
        dados = {
            "_csrf_token": token, "vigente_desde": "2026-01-01", "carga_diaria": "08:00",
            "dias_trabalho": ["0", "1", "2", "3", "4"], "intervalo_minimo_min": "60",
            "interjornada": "11:00", "tolerancia_marcacao_min": "5", "tolerancia_diaria_min": "10",
            "extra_util_pct": "50", "extra_descanso_pct": "100", "limite_extras_dia_min": "120",
            "noturno_pct": "20",
        }
        dados.update(extra)
        return dados

    def test_jornada_padrao_reproduz_regras_originais(self):
        with self.app.app_context():
            m = self.module
            j = m.jornada_vigente(m.date(2026, 11, 12))
            self.assertTrue(j.padrao)
            self.assertEqual((j.carga_diaria_min, j.dias_trabalho, j.interjornada_min), (480, (0, 1, 2, 3, 4), 660))
            self.assertFalse(m.eh_dia_util(m.date(2026, 11, 14)))  # sábado

    def test_ti_salva_parametros_com_vigencia_e_historico(self):
        self.make_user(email="ti@example.com", ti=True)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            self.assertEqual(client.get("/admin/fragment/parametros").status_code, 200)
            token = self.csrf(client, "/admin")
            # Versão 1: 8h48 de segunda a sexta desde jan/2026.
            client.post("/admin/parametros", data=self._form_jornada(token, carga_diaria="08:48"))
            # Versão 2: inclui sábado a partir de 01/12/2026.
            client.post("/admin/parametros", data=self._form_jornada(
                token, vigente_desde="2026-12-01", carga_diaria="08:48",
                dias_trabalho=["0", "1", "2", "3", "4", "5"]))
            # Reenviar sem mudanças não cria versão nova.
            client.post("/admin/parametros", data=self._form_jornada(
                token, vigente_desde="2026-12-01", carga_diaria="08:48",
                dias_trabalho=["0", "1", "2", "3", "4", "5"]))
            html = client.get("/admin/fragment/parametros").get_data(as_text=True)
            self.assertIn("Histórico de versões", html)

        with self.app.app_context():
            m = self.module
            self.assertEqual(m.ParametroJornada.query.count(), 2)
            nov = m.jornada_vigente(m.date(2026, 11, 14))
            dez = m.jornada_vigente(m.date(2026, 12, 5))
            self.assertEqual(nov.carga_diaria_min, 528)
            self.assertFalse(m.eh_dia_util(m.date(2026, 11, 14)))  # sábado de novembro: folga
            self.assertTrue(m.eh_dia_util(m.date(2026, 12, 5)))    # sábado de dezembro: trabalho
            self.assertEqual(dez.dias_trabalho, (0, 1, 2, 3, 4, 5))
            self.assertEqual(m.jornada_vigente(m.date(2025, 12, 31)).carga_diaria_min, 480)  # antes: padrão
            logs = [l.acao for l in m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Alterou parâmetros%")).all()]
            self.assertEqual(len(logs), 2)
            self.assertIn("Carga diária: 8h -> 8h48", logs[0])
            self.assertIn("Dias de trabalho: Seg, Ter, Qua, Qui, Sex -> Seg, Ter, Qua, Qui, Sex, Sáb", logs[1])

    def test_parametros_validam_limites_legais(self):
        self.make_user(email="ti@example.com", ti=True)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            for invalido in (
                {"tolerancia_marcacao_min": "6"},       # acima de 5 min
                {"tolerancia_diaria_min": "3"},         # menor que por marcação
                {"extra_util_pct": "40"},               # abaixo de 50%
                {"interjornada": "10:00"},              # abaixo de 11h
                {"carga_diaria": "abc"},
                {"dias_trabalho": []},
                {"vigente_desde": ""},
            ):
                client.post("/admin/parametros", data=self._form_jornada(token, **invalido))
        with self.app.app_context():
            self.assertEqual(self.module.ParametroJornada.query.count(), 0)

    def test_rh_nao_altera_parametros(self):
        self.make_user(email="rh@example.com", rh=True)
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            self.assertIn(client.get("/admin/fragment/parametros").status_code, (302, 403))
            token = self.csrf(client, "/admin")
            client.post("/admin/parametros", data=self._form_jornada(token, carga_diaria="06:00"))
        with self.app.app_context():
            self.assertEqual(self.module.ParametroJornada.query.count(), 0)

    def test_relatorio_usa_carga_vigente_no_dia(self):
        user_id = self.make_user()
        with self.app.app_context():
            m = self.module
            m.db.session.add(m.ParametroJornada(
                vigente_desde=m.date(2026, 11, 4), carga_diaria_min=360, dias_trabalho="0,1,2,3,4",
                tolerancia_marcacao_min=5, tolerancia_diaria_min=10, intervalo_minimo_min=60,
                interjornada_min=660, limite_extras_dia_min=120, extra_util_pct=50,
                extra_descanso_pct=100, noturno_ativo=False, noturno_pct=20,
            ))
            # Ter 03/11 e Qua 04/11: 7h trabalhadas em cada dia.
            for dia in ("03/11/2026", "04/11/2026"):
                m.db.session.add(m.RegistroPonto(data=dia, tipo="Entrada", hora="08:00:00", usuario_id=user_id))
                m.db.session.add(m.RegistroPonto(data=dia, tipo="Saída", hora="15:00:00", usuario_id=user_id))
            m.db.session.commit()
            user = m.db.session.get(m.Usuario, user_id)
            dados = m._gerar_relatorio_ponto_dados(user, "2026-11-03", "2026-11-04")
            # 03/11 (regra 8h): falta 1h. 04/11 (regra 6h): 1h extra.
            self.assertEqual(dados["total_segundos_faltantes"], 3600)
            self.assertEqual(dados["total_segundos_extras"], 3600)

    # ------------------------------------------------------------------
    # Setores com carga própria e prazo de correção
    # ------------------------------------------------------------------
    def _criar_setor(self, client, token, nome, carga=None, dias=("0", "1", "2", "3", "4")):
        dados = {"_csrf_token": token, "nome": nome}
        if carga:
            dados.update({"carga_propria": "on", "carga_diaria": carga, "dias_trabalho": list(dias)})
        return client.post("/admin/departamentos", data=dados)

    def test_setor_com_carga_propria_vale_so_para_seus_membros(self):
        self.make_user(email="ti@example.com", ti=True)
        membro_id = self.make_user(email="membro@example.com")
        outro_id = self.make_user(email="outro@example.com")
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            # Setor de 6h que também trabalha no sábado.
            self._criar_setor(client, token, "Suporte", carga="06:00", dias=("0", "1", "2", "3", "4", "5"))
            self._criar_setor(client, token, "suporte", carga="07:00")  # nome repetido (caixa diferente)
            self._criar_setor(client, token, "Comercial")  # sem carga própria
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.Departamento.query.count(), 2)
            suporte = m.Departamento.query.filter_by(nome="Suporte").one()
            m.db.session.get(m.Usuario, membro_id).departamento_id = suporte.id
            m.db.session.commit()
            # A carga do setor vale a partir do dia da criação (hoje).
            hoje = m.datetime.now(m.ZoneInfo("America/Sao_Paulo")).date()
            j = m.jornada_vigente(hoje, suporte.id)
            self.assertEqual((j.carga_diaria_min, j.setor), (360, "Suporte"))
            self.assertEqual(m.jornada_vigente(hoje).carga_diaria_min, 480)
            comercial = m.Departamento.query.filter_by(nome="Comercial").one()
            self.assertIsNone(m.jornada_vigente(hoje, comercial.id).setor)
            sabado = hoje + m.timedelta(days=(5 - hoje.weekday()) % 7)
            self.assertTrue(m.eh_dia_util(sabado, suporte.id) or sabado in m._feriados_do_mes(sabado))
            self.assertFalse(m.eh_dia_util(sabado))

    def test_editar_carga_do_setor_com_vigencia(self):
        self.make_user(email="ti@example.com", ti=True)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            self._criar_setor(client, token, "Operação", carga="08:00")
            with self.app.app_context():
                dep_id = self.module.Departamento.query.filter_by(nome="Operação").one().id
            client.post(f"/admin/departamentos/{dep_id}/editar", data={
                "_csrf_token": token, "nome": "Operações", "carga_propria": "on", "carga_diaria": "07:20",
                "dias_trabalho": ["0", "1", "2", "3", "4"], "vigente_desde": "2027-01-01"})
            html = client.get("/admin/fragment/parametros").get_data(as_text=True)
            self.assertIn("Setores e cargas horárias", html)
            self.assertIn("Operações", html)
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.jornada_vigente(m.date(2026, 12, 31), dep_id).carga_diaria_min, 480)
            self.assertEqual(m.jornada_vigente(m.date(2027, 1, 4), dep_id).carga_diaria_min, 440)
            log = m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Alterou o setor%")).one()
            self.assertIn("nome: Operação -> Operações", log.acao)
            self.assertIn("8h", log.acao)
            self.assertIn("7h20", log.acao)

    def test_relatorio_usa_carga_do_setor(self):
        user_id = self.make_user()
        with self.app.app_context():
            m = self.module
            dep = m.Departamento(nome="Meio período")
            m.db.session.add(dep)
            m.db.session.flush()
            m.db.session.add(m.JornadaSetor(departamento_id=dep.id, vigente_desde=m.date(2026, 1, 1),
                                            carga_diaria_min=240, dias_trabalho="0,1,2,3,4"))
            m.db.session.get(m.Usuario, user_id).departamento_id = dep.id
            m.db.session.add(m.RegistroPonto(data="03/11/2026", tipo="Entrada", hora="08:00:00", usuario_id=user_id))
            m.db.session.add(m.RegistroPonto(data="03/11/2026", tipo="Saída", hora="13:00:00", usuario_id=user_id))
            m.db.session.commit()
            dados = m._gerar_relatorio_ponto_dados(m.db.session.get(m.Usuario, user_id), "2026-11-03", "2026-11-03")
            self.assertEqual(dados["total_segundos_extras"], 3600)   # 5h trabalhadas - 4h do setor
            self.assertEqual(dados["total_segundos_faltantes"], 0)

    def test_setor_com_colaboradores_nao_pode_ser_excluido_e_rh_nao_gerencia(self):
        self.make_user(email="ti@example.com", ti=True)
        self.make_user(email="rh@example.com", rh=True)
        membro_id = self.make_user(email="membro@example.com")
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            self._criar_setor(client, token, "Financeiro", carga="08:00")
        with self.app.app_context():
            m = self.module
            dep = m.Departamento.query.filter_by(nome="Financeiro").one()
            m.db.session.get(m.Usuario, membro_id).departamento_id = dep.id
            m.db.session.commit()
            dep_id = dep.id
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            client.post(f"/admin/departamentos/excluir/{dep_id}", data={"_csrf_token": token})
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            self._criar_setor(client, token, "Do RH", carga="04:00")
            client.post(f"/admin/departamentos/{dep_id}/editar", data={
                "_csrf_token": token, "nome": "X", "vigente_desde": "2026-11-01"})
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.db.session.get(m.Departamento, dep_id).nome, "Financeiro")
            self.assertIsNone(m.Departamento.query.filter_by(nome="Do RH").first())

    def test_janela_de_correcao_ate_dia_anterior_ao_fechamento(self):
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.janela_correcao(m.date(2026, 11, 12)),
                             (m.date(2026, 11, 1), m.date(2026, 11, 30), m.date(2026, 11, 29)))
            self.assertEqual(m.janela_correcao(m.date(2026, 2, 3))[2], m.date(2026, 2, 27))
            m._set_config("correcao_dias_antes_fechamento", "3")
            m.db.session.commit()
            self.assertEqual(m.janela_correcao(m.date(2026, 11, 12))[2], m.date(2026, 11, 27))

    def test_correcao_de_mes_fechado_e_recusada(self):
        self.make_user()
        hoje = self.module.datetime.now(self.module.ZoneInfo("America/Sao_Paulo")).date()
        mes_passado = hoje.replace(day=1) - self.module.timedelta(days=1)
        with self.app.test_client() as client:
            self.login(client)
            token = self.csrf(client, "/solicitar-correcao")
            base = {"_csrf_token": token, "tipo_ponto": "Entrada", "hora_correta": "08:00", "justificativa": "esqueci"}
            client.post("/solicitar-correcao", data={**base, "data_ponto": mes_passado.isoformat()})
            client.post("/solicitar-correcao", data={**base, "data_ponto": hoje.isoformat()})
        with self.app.app_context():
            m = self.module
            datas = [s.data_ponto for s in m.SolicitacaoCorrecao.query.all()]
            self.assertNotIn(mes_passado.strftime("%d/%m/%Y"), datas)
            if hoje <= m.janela_correcao(hoje)[2]:
                self.assertIn(hoje.strftime("%d/%m/%Y"), datas)
            else:
                self.assertNotIn(hoje.strftime("%d/%m/%Y"), datas)

    def test_ti_ajusta_prazo_de_correcao(self):
        self.make_user(email="ti@example.com", ti=True)
        self.make_user(email="rh@example.com", rh=True)
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post("/admin/parametros/correcao", data={"_csrf_token": token, "correcao_dias_antes_fechamento": "5"})
        with self.app.app_context():
            self.assertEqual(self.module.correcao_dias_antes_fechamento(), 1)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            client.post("/admin/parametros/correcao", data={"_csrf_token": token, "correcao_dias_antes_fechamento": "40"})
            client.post("/admin/parametros/correcao", data={"_csrf_token": token, "correcao_dias_antes_fechamento": "2"})
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.correcao_dias_antes_fechamento(), 2)
            self.assertEqual(m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Alterou o prazo de correção%")).count(), 1)

    # ------------------------------------------------------------------
    # Lembretes de ponto e push
    # ------------------------------------------------------------------
    def _jornada_com_horario(self, entrada=480, saida=1020, desde=None):
        m = self.module
        m.db.session.add(m.ParametroJornada(
            vigente_desde=desde or m.date(2026, 1, 1), carga_diaria_min=480, dias_trabalho="0,1,2,3,4",
            tolerancia_marcacao_min=5, tolerancia_diaria_min=10, intervalo_minimo_min=60,
            interjornada_min=660, limite_extras_dia_min=120, extra_util_pct=50,
            extra_descanso_pct=100, noturno_ativo=False, noturno_pct=20,
            horario_entrada_min=entrada, horario_saida_min=saida,
        ))
        m.db.session.commit()

    def _agora(self, hh, mm, dia=17):
        m = self.module
        return m.datetime(2026, 11, dia, hh, mm, tzinfo=m.ZoneInfo("America/Sao_Paulo"))  # 17/11/2026 = terça

    def _tipos(self, agora, user_id):
        return sorted(d["tipo"] for d in self.module.lembretes_devidos(agora) if d["usuario"].id == user_id)

    def test_lembretes_de_entrada_saida_e_esquecimento(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            self._jornada_com_horario()  # 08:00 às 17:00
            self.assertEqual(self._tipos(self._agora(7, 50), uid), ["entrada_10"])
            self.assertEqual(self._tipos(self._agora(7, 53), uid), ["entrada_10"])  # janela tolera atraso
            self.assertEqual(self._tipos(self._agora(7, 55), uid), ["entrada_5"])
            self.assertEqual(self._tipos(self._agora(8, 10), uid), [])
            self.assertEqual(self._tipos(self._agora(8, 15), uid), ["esqueceu_entrada"])
            # Bateu a entrada: some o aviso e, à tarde, vêm os lembretes de saída.
            m.db.session.add(m.RegistroPonto(data="17/11/2026", tipo="Entrada", hora="08:20:00", usuario_id=uid))
            m.db.session.commit()
            self.assertEqual(self._tipos(self._agora(8, 30), uid), [])
            self.assertEqual(self._tipos(self._agora(16, 50), uid), ["saida_10"])
            self.assertEqual(self._tipos(self._agora(16, 55), uid), ["saida_5"])
            # Já bateu a saída: sem lembrete.
            m.db.session.add(m.RegistroPonto(data="17/11/2026", tipo="Saída", hora="16:40:00", usuario_id=uid))
            m.db.session.commit()
            self.assertEqual(self._tipos(self._agora(16, 50), uid), [])
            # Sábado (fora dos dias de trabalho): nada.
            self.assertEqual(self._tipos(self._agora(7, 50, dia=21), uid), [])
            # Desligado pela TI: nada.
            m._set_config("lembretes_ativos", "false")
            m.db.session.commit()
            self.assertEqual(self._tipos(self._agora(7, 50, dia=18), uid), [])

    def test_sem_horario_definido_nao_ha_lembretes(self):
        uid = self.make_user()
        with self.app.app_context():
            self.assertEqual(self._tipos(self._agora(7, 50), uid), [])
            self.assertEqual(self._tipos(self._agora(9, 0), uid), [])

    def test_horario_do_setor_substitui_o_padrao(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            self._jornada_com_horario()  # padrão 08:00
            dep = m.Departamento(nome="Turno tarde")
            m.db.session.add(dep)
            m.db.session.flush()
            m.db.session.add(m.JornadaSetor(departamento_id=dep.id, vigente_desde=m.date(2026, 1, 1), carga_diaria_min=360,
                                            dias_trabalho="0,1,2,3,4", horario_entrada_min=780, horario_saida_min=1140))
            m.db.session.get(m.Usuario, uid).departamento_id = dep.id
            m.db.session.commit()
            self.assertEqual(self._tipos(self._agora(7, 50), uid), [])
            self.assertEqual(self._tipos(self._agora(12, 50), uid), ["entrada_10"])

    def test_processar_lembretes_envia_uma_vez_e_salva_no_sino(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            self._jornada_com_horario()
            with patch.object(m, "enviar_push", return_value=1) as push:
                self.assertEqual(m.processar_lembretes(self._agora(8, 15)), 1)
                self.assertEqual(m.processar_lembretes(self._agora(8, 16)), 0)  # mesmo dia/tipo: não repete
                self.assertEqual(push.call_count, 1)
                self.assertEqual(push.call_args[0][0], uid)
            self.assertEqual(m.LembreteEnviado.query.filter_by(usuario_id=uid, tipo="esqueceu_entrada").count(), 1)
            notif = m.Notificacao.query.filter_by(usuario_id=uid).one()
            self.assertIn("ainda não bateu a entrada", notif.titulo)
            # Lembrete de antecedência não vai para o sino.
            with patch.object(m, "enviar_push", return_value=1):
                m.processar_lembretes(self._agora(7, 50, dia=18))
            self.assertEqual(m.Notificacao.query.filter_by(usuario_id=uid).count(), 1)

    def test_inscricao_de_push(self):
        uid = self.make_user()
        insc = {"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": {"p256dh": "chave-p256", "auth": "segredo"}}
        with self.app.test_client() as client:
            # Sem login e sem CSRF: recusado.
            self.assertEqual(client.post("/api/push/inscrever", json=insc).status_code, 403)
            self.login(client)
            token = self.csrf(client, "/")
            h = {"X-CSRF-Token": token}
            self.assertTrue(client.get("/api/push/chave").get_json()["ativo"] in (True, False))
            with patch.object(self.module, "VAPID", {"publica": "x", "privada": "y", "claim": "mailto:a@b.c"}):
                self.assertEqual(client.post("/api/push/inscrever", json={"endpoint": "http://inseguro"}, headers=h).status_code, 400)
                self.assertEqual(client.post("/api/push/inscrever", json=insc, headers=h).status_code, 200)
                self.assertEqual(client.post("/api/push/inscrever", json=insc, headers=h).status_code, 200)  # sem duplicar
            with self.app.app_context():
                self.assertEqual(self.module.PushInscricao.query.filter_by(usuario_id=uid).count(), 1)
            self.assertEqual(client.post("/api/push/cancelar", json={"endpoint": insc["endpoint"]}, headers=h).status_code, 200)
            with self.app.app_context():
                self.assertEqual(self.module.PushInscricao.query.count(), 0)

    def test_push_expirado_remove_inscricao(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            m.db.session.add(m.PushInscricao(usuario_id=uid, endpoint="https://push.example/1", endpoint_hash="h1", p256dh="p", auth="a"))
            m.db.session.commit()
            from pywebpush import WebPushException

            class Resp:
                status_code = 410
            with patch.object(m, "VAPID", {"publica": "x", "privada": "y", "claim": "mailto:a@b.c"}), \
                 patch("pywebpush.webpush", side_effect=WebPushException("gone", response=Resp())):
                self.assertEqual(m.enviar_push(uid, "t", "c"), 0)
            self.assertEqual(m.PushInscricao.query.count(), 0)

    def test_service_worker_e_manifesto(self):
        with self.app.test_client() as client:
            r = client.get("/sw.js")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers.get("Service-Worker-Allowed"), "/")
            self.assertIn("showNotification", r.get_data(as_text=True))
            r.close()
            man = client.get("/manifest.webmanifest")
            self.assertEqual(man.get_json()["display"], "standalone")
            self.assertEqual(client.get("/static/icons/icon-192.png").status_code, 200)

    def test_horarios_da_jornada_e_lembretes_pela_ti(self):
        self.make_user(email="ti@example.com", ti=True)
        self.make_user(email="rh@example.com", rh=True)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            # Saída antes da entrada e só um horário: recusados.
            client.post("/admin/parametros", data=self._form_jornada(token, horario_entrada="18:00", horario_saida="08:00"))
            client.post("/admin/parametros", data=self._form_jornada(token, horario_entrada="08:00"))
            with self.app.app_context():
                self.assertEqual(self.module.ParametroJornada.query.count(), 0)
            client.post("/admin/parametros", data=self._form_jornada(token, horario_entrada="08:00", horario_saida="17:48"))
            client.post("/admin/parametros/lembretes", data={"_csrf_token": token, "lembretes_ativos": "on",
                        "lembrete_antecedencia_1": "15", "lembrete_antecedencia_2": "5", "lembrete_esquecimento_min": "20"})
            html = client.get("/admin/fragment/parametros").get_data(as_text=True)
            self.assertIn("Lembretes de ponto", html)
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post("/admin/parametros/lembretes", data={"_csrf_token": token,
                        "lembrete_antecedencia_1": "1", "lembrete_antecedencia_2": "1", "lembrete_esquecimento_min": "5"})
        with self.app.app_context():
            m = self.module
            j = m.jornada_vigente(m.date(2026, 1, 2))
            self.assertEqual((j.horario_entrada_min, j.horario_saida_min), (480, 1068))
            cfg = m.config_lembretes()
            self.assertEqual((cfg["antecedencias"], cfg["esquecimento_min"], cfg["ativos"]), ([15, 5], 20, True))

    # ------------------------------------------------------------------
    # Afastamentos (férias, atestados, folgas)
    # ------------------------------------------------------------------
    def _lancar(self, client, token, uid, tipo="ferias", ini="2026-11-02", fim="2026-11-06", anexo=None, **extra):
        dados = {"_csrf_token": token, "usuario_id": str(uid), "tipo": tipo, "data_inicio": ini, "data_fim": fim, **extra}
        if anexo is not None:
            dados["anexo"] = anexo
        return client.post("/admin/afastamentos", data=dados, content_type="multipart/form-data")

    def test_rh_lanca_afastamento_com_validacoes(self):
        self.make_user(email="rh@example.com", rh=True)
        self.make_user(email="ti@example.com", ti=True)
        uid = self.make_user(email="func@example.com")
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            self.assertEqual(client.get("/admin/fragment/afastamentos").status_code, 200)
            self._lancar(client, token, uid)                                       # ok
            self._lancar(client, token, uid, ini="2026-11-05", fim="2026-11-10")   # sobrepõe
            self._lancar(client, token, uid, ini="2026-11-20", fim="2026-11-10")   # fim antes do início
            self._lancar(client, token, uid, tipo="inventado", ini="2026-12-01", fim="2026-12-02")
            self._lancar(client, token, uid, tipo="atestado", ini="2026-11-09", fim="2026-11-09")  # ok (encosta, não sobrepõe)
            html = client.get("/admin/fragment/afastamentos").get_data(as_text=True)
            self.assertIn("Férias", html)
        # TI e colaborador não lançam.
        for email in ("ti@example.com", "func@example.com"):
            with self.app.test_client() as client:
                self.login(client, email=email)
                token = self.csrf(client, "/")
                self._lancar(client, token, uid, ini="2026-12-10", fim="2026-12-11")
        with self.app.app_context():
            m = self.module
            self.assertEqual(sorted(a.tipo for a in m.Afastamento.query.all()), ["atestado", "ferias"])
            log = m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Lançou afastamento (Férias)%")).one()
            self.assertIn("02/11/2026 a 06/11/2026", log.acao)

    def test_afastamento_abona_dias_no_relatorio_historico_e_notificacoes(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            # Semana de 09 a 13/11: férias na terça e quarta (10 e 11); demais dias sem ponto.
            m.db.session.add(m.Afastamento(usuario_id=uid, tipo="ferias", data_inicio=m.date(2026, 11, 10), data_fim=m.date(2026, 11, 11)))
            m.db.session.commit()
            dados = m._gerar_relatorio_ponto_dados(m.db.session.get(m.Usuario, uid), "2026-11-09", "2026-11-11")
            linhas = {l[0]: l[-1] for l in dados["tabela_linhas"][1:]}
            self.assertEqual(linhas["09/11/2026"], "FALTA")
            self.assertEqual(linhas["10/11/2026"], "FÉRIAS")
            self.assertEqual(linhas["11/11/2026"], "FÉRIAS")
            self.assertEqual(dados["total_faltas_dias"], 1)
            self.assertEqual(dados["total_dias_afastados"], 2)
            self.assertTrue(m.afastamento_no_dia(uid, m.date(2026, 11, 10)))
            self.assertIsNone(m.afastamento_no_dia(uid, m.date(2026, 11, 12)))
        with self.app.test_client() as client:
            self.login(client)
            html = client.get("/meu_historico?data_inicio=2026-11-09&data_fim=2026-11-11").get_data(as_text=True)
            self.assertIn("Férias (dia abonado)", html)

    def test_afastado_nao_recebe_lembrete(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            self._jornada_com_horario()
            m.db.session.add(m.Afastamento(usuario_id=uid, tipo="atestado", data_inicio=m.date(2026, 11, 17), data_fim=m.date(2026, 11, 17)))
            m.db.session.commit()
            self.assertEqual(self._tipos(self._agora(8, 15), uid), [])
            self.assertEqual(self._tipos(self._agora(8, 15, dia=18), uid), ["esqueceu_entrada"])

    def test_anexo_de_atestado_so_para_o_rh(self):
        import io as _io
        self.make_user(email="rh@example.com", rh=True)
        self.make_user(email="ti@example.com", ti=True)
        uid = self.make_user(email="func@example.com")
        pdf = b"%PDF-1.4\n% atestado de teste\n"
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            # Extensão .pdf, mas conteúdo não é PDF: recusado.
            self._lancar(client, token, uid, tipo="atestado", anexo=(_io.BytesIO(b"<script>x</script>"), "falso.pdf"))
            self._lancar(client, token, uid, tipo="atestado", anexo=(_io.BytesIO(pdf), "atestado medico.pdf"))
            with self.app.app_context():
                afast = self.module.Afastamento.query.one()
                aid = afast.id
                self.assertEqual((afast.anexo_tipo, afast.anexo_nome), ("application/pdf", "atestado_medico.pdf"))
            r = client.get(f"/admin/afastamentos/{aid}/anexo")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.data, pdf)
            self.assertEqual(r.headers.get("Cache-Control"), "no-store")
        for email in ("ti@example.com", "func@example.com"):
            with self.app.test_client() as client:
                self.login(client, email=email)
                self.assertIn(client.get(f"/admin/afastamentos/{aid}/anexo").status_code, (302, 403))
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Abriu o anexo%")).count(), 1)

    def test_cancelar_afastamento_volta_a_contar_falta(self):
        self.make_user(email="rh@example.com", rh=True)
        uid = self.make_user(email="func@example.com")
        with self.app.app_context():
            m = self.module
            a = m.Afastamento(usuario_id=uid, tipo="folga", data_inicio=m.date(2026, 11, 9), data_fim=m.date(2026, 11, 9))
            m.db.session.add(a)
            m.db.session.commit()
            aid = a.id
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post(f"/admin/afastamentos/{aid}/excluir", data={"_csrf_token": token})
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.Afastamento.query.count(), 0)
            dados = m._gerar_relatorio_ponto_dados(m.db.session.get(m.Usuario, uid), "2026-11-09", "2026-11-09")
            self.assertEqual(dados["total_faltas_dias"], 1)
            self.assertEqual(m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Cancelou afastamento%")).count(), 1)

    # ------------------------------------------------------------------
    # Lembrete geral do painel e avisos no sino
    # ------------------------------------------------------------------
    def test_lembrete_geral_aparece_no_sino_e_vai_por_push(self):
        self.make_user(email="rh@example.com", rh=True)
        uid = self.make_user(email="func@example.com")
        outro = self.make_user(email="outro@example.com")
        with self.app.app_context():
            m = self.module
            m.db.session.add(m.PushInscricao(usuario_id=uid, endpoint="https://push.example/x", endpoint_hash="hx", p256dh="p", auth="a"))
            m.db.session.commit()
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            with patch.object(self.module, "VAPID", {"publica": "x", "privada": "y", "claim": "mailto:a@b.c"}), \
                 patch.object(self.module, "enviar_push", return_value=1) as push:
                client.post("/admin/enviar-lembrete-geral", data={"_csrf_token": token, "mensagem": "Reunião geral às 16h"})
                self.assertEqual([c.args[0] for c in push.call_args_list], [uid])  # só quem tem aparelho inscrito
        with self.app.test_client() as client:
            self.login(client, email="func@example.com")
            html = client.get("/").get_data(as_text=True)
            self.assertIn("Reunião geral às 16h", html)
            self.assertIn("Marcar avisos como lidos", html)
            with self.app.app_context():
                m = self.module
                aviso = m.Notificacao.query.filter_by(usuario_id=uid).one()
                aviso_outro = m.Notificacao.query.filter_by(usuario_id=outro).one()
            # Não abre aviso de outra pessoa.
            self.assertEqual(client.get(f"/notificacoes/{aviso_outro.id}/abrir").status_code, 404)
            r = client.get(f"/notificacoes/{aviso.id}/abrir")
            self.assertEqual((r.status_code, r.location), (302, "/"))
            self.assertNotIn("Reunião geral às 16h", client.get("/").get_data(as_text=True))
        with self.app.app_context():
            m = self.module
            self.assertTrue(m.db.session.get(m.Notificacao, aviso.id).lida)
            self.assertFalse(m.db.session.get(m.Notificacao, aviso_outro.id).lida)
            self.assertEqual(m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Enviou lembrete geral%")).count(), 1)

    # ------------------------------------------------------------------
    # Apuração de horas (etapa 3)
    # ------------------------------------------------------------------
    def _apurar(self, uid, data, batidas, saida_anterior=None):
        m = self.module
        return m.apurar_dia(m.db.session.get(m.Usuario, uid), data, batidas,
                            hoje=m.date(2026, 11, 30), saida_anterior=saida_anterior)

    def test_apuracao_tolerancia_extras_e_atrasos(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            ter = m.date(2026, 11, 17)  # dia útil, carga padrão 8h
            dia = lambda e1, s1, e2, s2: [("Entrada", e1), ("Saída", s1), ("Entrada", e2), ("Saída", s2)]
            # +8 min: dentro da tolerância diária (10) -> nada conta.
            ap = self._apurar(uid, ter, dia("08:00:00", "12:00:00", "13:00:00", "17:08:00"))
            self.assertEqual((ap.extra_50, ap.atraso, ap.tolerado), (0, 0, True))
            # +15 min: passou da tolerância -> conta tudo (Súmula 366).
            ap = self._apurar(uid, ter, dia("08:00:00", "12:00:00", "13:00:00", "17:15:00"))
            self.assertEqual((ap.extra_50, ap.tolerado), (15 * 60, False))
            # -40 min: atraso.
            ap = self._apurar(uid, ter, dia("08:40:00", "12:00:00", "13:00:00", "17:00:00"))
            self.assertEqual((ap.atraso, ap.extra_50), (40 * 60, 0))
            # Sem batida em dia útil: falta do dia inteiro.
            ap = self._apurar(uid, ter, [])
            self.assertTrue(ap.falta)
            self.assertEqual(ap.falta_seg, 8 * 3600)
            # Entrada sem saída: incompleto, sem calcular extra nem atraso.
            ap = self._apurar(uid, ter, [("Entrada", "08:00:00")])
            self.assertTrue(ap.incompleto)
            self.assertEqual((ap.extra_50, ap.atraso), (0, 0))

    def test_apuracao_tolerancia_por_marcacao_com_horario_fixo(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            self._jornada_com_horario(entrada=480, saida=1020)  # 08:00–17:00, carga 8h
            ter = m.date(2026, 11, 17)
            # Chegou 7 min atrasado e saiu 7 min depois: total 0, mas cada marcação passou de 5 min.
            ap = self._apurar(uid, ter, [("Entrada", "08:07:00"), ("Saída", "12:00:00"), ("Entrada", "13:00:00"), ("Saída", "17:07:00")])
            self.assertEqual(ap.trabalhado, 8 * 3600)
            self.assertFalse(ap.tolerado)  # diferença 0: nada a tolerar nem pagar
            # Entrada 08:04 e saída 17:08 (4 + 8 min): marcação da saída passa de 5 -> conta.
            ap = self._apurar(uid, ter, [("Entrada", "08:04:00"), ("Saída", "12:00:00"), ("Entrada", "13:00:00"), ("Saída", "17:08:00")])
            self.assertEqual((ap.extra_50, ap.tolerado), (4 * 60, False))
            # Entrada 07:57 e saída 17:02 (3 + 2 min): dentro -> tolerado.
            ap = self._apurar(uid, ter, [("Entrada", "07:57:00"), ("Saída", "12:00:00"), ("Entrada", "13:00:00"), ("Saída", "17:02:00")])
            self.assertEqual((ap.extra_50, ap.tolerado), (0, True))

    def test_apuracao_domingo_feriado_e_folga(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            turno = [("Entrada", "08:00:00"), ("Saída", "12:00:00")]
            sab = self._apurar(uid, m.date(2026, 11, 21), turno)
            dom = self._apurar(uid, m.date(2026, 11, 22), turno)
            fer = self._apurar(uid, m.date(2026, 11, 20), turno)  # Consciência Negra (nacional)
            self.assertEqual((sab.tipo_dia, sab.extra_50, sab.extra_100), ("descanso", 4 * 3600, 0))
            self.assertEqual((dom.tipo_dia, dom.extra_50, dom.extra_100), ("domingo", 0, 4 * 3600))
            self.assertEqual((fer.tipo_dia, fer.extra_100), ("feriado", 4 * 3600))
            # Folga sem batida não é falta.
            self.assertFalse(self._apurar(uid, m.date(2026, 11, 21), []).falta)

    def test_apuracao_alertas_e_noturno(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            ter = m.date(2026, 11, 17)
            # 11h seguidas: extras acima de 2h e sem intervalo.
            ap = self._apurar(uid, ter, [("Entrada", "08:00:00"), ("Saída", "19:00:00")])
            self.assertEqual(ap.extra_50, 3 * 3600)
            self.assertIn("Extras acima de 02:00", ap.alertas)
            self.assertIn("Sem intervalo", ap.alertas)
            # Intervalo de 30 min numa jornada de 8h.
            ap = self._apurar(uid, ter, [("Entrada", "08:00:00"), ("Saída", "12:00:00"), ("Entrada", "12:30:00"), ("Saída", "16:30:00")])
            self.assertIn("Intervalo de 30 min", ap.alertas)
            # Interjornada: saiu 23:00 na véspera e entrou 08:00 (9h de descanso).
            ap = self._apurar(uid, ter, [("Entrada", "08:00:00"), ("Saída", "12:00:00"), ("Entrada", "13:00:00"), ("Saída", "17:00:00")],
                              saida_anterior=m.datetime(2026, 11, 16, 23, 0))
            self.assertIn("Interjornada curta", ap.alertas)
            # Noturno: 20:00–23:00 tem 1h entre 22h e 5h.
            ap = self._apurar(uid, m.date(2026, 11, 21), [("Entrada", "20:00:00"), ("Saída", "23:00:00")])
            self.assertEqual(ap.noturno, 3600)

    def test_apuracao_periodo_nao_compensa_extra_com_atraso(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            m.db.session.add_all([
                # Seg 16/11: 2h extras. Ter 17/11: 1h de atraso. Qua 18/11: afastado. Qui 19/11: falta.
                m.RegistroPonto(data="16/11/2026", tipo="Entrada", hora="08:00:00", usuario_id=uid),
                m.RegistroPonto(data="16/11/2026", tipo="Saída", hora="12:00:00", usuario_id=uid),
                m.RegistroPonto(data="16/11/2026", tipo="Entrada", hora="13:00:00", usuario_id=uid),
                m.RegistroPonto(data="16/11/2026", tipo="Saída", hora="19:00:00", usuario_id=uid),
                m.RegistroPonto(data="17/11/2026", tipo="Entrada", hora="09:00:00", usuario_id=uid),
                m.RegistroPonto(data="17/11/2026", tipo="Saída", hora="12:00:00", usuario_id=uid),
                m.RegistroPonto(data="17/11/2026", tipo="Entrada", hora="13:00:00", usuario_id=uid),
                m.RegistroPonto(data="17/11/2026", tipo="Saída", hora="17:00:00", usuario_id=uid),
                m.Afastamento(usuario_id=uid, tipo="atestado", data_inicio=m.date(2026, 11, 18), data_fim=m.date(2026, 11, 18)),
            ])
            m.db.session.commit()
            dias, tot = m.apurar_periodo(m.db.session.get(m.Usuario, uid), m.date(2026, 11, 16), m.date(2026, 11, 19),
                                         hoje=m.date(2026, 11, 30))
            self.assertEqual((tot["extra_50"], tot["atraso"], tot["faltas_dias"], tot["afastados_dias"]),
                             (2 * 3600, 3600, 1, 1))
            self.assertEqual([d.situacao for d in dias], ["Ok", "Ok", "ATESTADO MÉDICO", "FALTA"])

    # ------------------------------------------------------------------
    # Fechamento do mês (etapa 4)
    # ------------------------------------------------------------------
    def _preparar_outubro(self):
        """RH + colaborador cadastrados antes de outubro, com 2 dias de ponto."""
        rh = self.make_user(email="rh@example.com", rh=True)
        uid = self.make_user(email="func@example.com")
        with self.app.app_context():
            m = self.module
            for i in (rh, uid):
                m.db.session.get(m.Usuario, i).data_cadastro = m.datetime(2026, 9, 1)
            for d in ("01/10/2026", "02/10/2026"):
                m.db.session.add(m.RegistroPonto(data=d, tipo="Entrada", hora="08:00:00", usuario_id=uid))
                m.db.session.add(m.RegistroPonto(data=d, tipo="Saída", hora="12:00:00", usuario_id=uid))
                m.db.session.add(m.RegistroPonto(data=d, tipo="Entrada", hora="13:00:00", usuario_id=uid))
                m.db.session.add(m.RegistroPonto(data=d, tipo="Saída", hora="18:00:00", usuario_id=uid))
            m.db.session.commit()
        return rh, uid

    def test_fechar_mes_gera_espelhos_e_trava_edicoes(self):
        rh, uid = self._preparar_outubro()
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            self.assertEqual(client.get("/admin/fragment/fechamento?mes=2026-10").status_code, 200)
            # Mês corrente não pode ser fechado.
            hoje = self.module.datetime.now(self.module.ZoneInfo("America/Sao_Paulo")).date()
            client.post(f"/admin/fechamento/{hoje.year}/{hoje.month}/fechar", data={"_csrf_token": token})
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token})
            with self.app.app_context():
                m = self.module
                self.assertEqual(m.FechamentoMes.query.count(), 1)
                f = m.FechamentoMes.query.one()
                self.assertTrue(f.fechado)
                esp = m.EspelhoMensal.query.filter_by(usuario_id=uid).one()
                self.assertEqual(esp.conteudo["totais"]["extra_50"], 2 * 3600)  # 9h nos dois dias
                self.assertEqual(esp.ciencia_status, "pendente")
                self.assertTrue(m.Notificacao.query.filter_by(usuario_id=uid).filter(m.Notificacao.titulo.like("Espelho de ponto%")).count())
                ponto_id = m.RegistroPonto.query.filter_by(usuario_id=uid).first().id
            # Travas
            client.post("/admin/lancar-ponto-manual", data={"_csrf_token": token, "usuario_id": str(uid), "data": "2026-10-05",
                                                          "tipo": "Entrada", "hora": "08:00", "justificativa": "x"})
            client.post(f"/admin/excluir-ponto/{ponto_id}", data={"_csrf_token": token})
            self._lancar(client, token, uid, ini="2026-10-20", fim="2026-11-03")  # afastamento tocando outubro
            client.post("/admin/parametros", data=self._form_jornada(token, vigente_desde="2026-10-15", carga_diaria="06:00"))
        with self.app.app_context():
            m = self.module
            self.assertIsNone(m.RegistroPonto.query.filter_by(data="05/10/2026").first())
            self.assertIsNotNone(m.db.session.get(m.RegistroPonto, ponto_id))
            self.assertEqual(m.Afastamento.query.count(), 0)
            self.assertEqual(m.ParametroJornada.query.count(), 0)

    def test_aprovar_correcao_de_mes_fechado_e_bloqueado(self):
        rh, uid = self._preparar_outubro()
        with self.app.app_context():
            m = self.module
            sol = m.SolicitacaoCorrecao(data_ponto="03/10/2026", tipo_ponto="Entrada", hora_correta="08:00:00",
                                        justificativa="esqueci", usuario_id=uid)
            m.db.session.add(sol)
            m.db.session.commit()
            sid = sol.id
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token})
            client.post(f"/admin/solicitacoes/{sid}/aprovar", data={"_csrf_token": token})
            with self.app.app_context():
                self.assertEqual(self.module.db.session.get(self.module.SolicitacaoCorrecao, sid).status, "Pendente")
                self.assertIsNone(self.module.RegistroPonto.query.filter_by(data="03/10/2026").first())
            client.post(f"/admin/solicitacoes/{sid}/recusar", data={"_csrf_token": token})
            with self.app.app_context():
                self.assertEqual(self.module.db.session.get(self.module.SolicitacaoCorrecao, sid).status, "Recusada")

    def test_ciencia_contestacao_e_reabertura(self):
        rh, uid = self._preparar_outubro()
        outro = self.make_user(email="outro@example.com")
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token_rh = self.csrf(client, "/admin")
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token_rh})
        with self.app.test_client() as client:
            self.login(client, email="func@example.com")
            self.assertIn("Espelho de outubro/2026", client.get("/").get_data(as_text=True))
            html = client.get("/espelho/2026/10").get_data(as_text=True)
            self.assertIn("Estou ciente", html)
            self.assertTrue(client.get("/espelho/2026/10/pdf").data.startswith(b"%PDF"))
            token = self.csrf(client, "/espelho/2026/10")
            client.post("/espelho/2026/10/ciencia", data={"_csrf_token": token, "acao": "contestar", "comentario": ""})
            with self.app.app_context():
                self.assertEqual(self.module.EspelhoMensal.query.filter_by(usuario_id=uid).one().ciencia_status, "pendente")
            client.post("/espelho/2026/10/ciencia", data={"_csrf_token": token, "acao": "ciente"})
        with self.app.test_client() as client:
            self.login(client, email="outro@example.com")
            self.assertEqual(client.get("/espelho/2026/10").status_code, 404)  # cadastrado depois de outubro
        with self.app.app_context():
            m = self.module
            esp = m.EspelhoMensal.query.filter_by(usuario_id=uid).one()
            self.assertEqual(esp.ciencia_status, "ciente")
            self.assertEqual(esp.ciencia_hash, esp.hash)
            hash_original = esp.hash
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token_rh = self.csrf(client, "/admin")
            # Reabrir exige motivo.
            client.post("/admin/fechamento/2026/10/reabrir", data={"_csrf_token": token_rh, "motivo": ""})
            with self.app.app_context():
                self.assertTrue(self.module.FechamentoMes.query.one().fechado)
            client.post("/admin/fechamento/2026/10/reabrir", data={"_csrf_token": token_rh, "motivo": "lançar ponto esquecido"})
            # Reaberto: edição liberada. Fecha de novo sem mudar nada -> ciência preservada.
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token_rh})
            with self.app.app_context():
                self.assertEqual(self.module.EspelhoMensal.query.filter_by(usuario_id=uid).one().ciencia_status, "ciente")
            client.post("/admin/fechamento/2026/10/reabrir", data={"_csrf_token": token_rh, "motivo": "faltou o dia 05"})
            client.post("/admin/lancar-ponto-manual", data={"_csrf_token": token_rh, "usuario_id": str(uid), "data": "2026-10-05",
                                                             "tipo": "Entrada", "hora": "08:00", "justificativa": "esquecido"})
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token_rh})
        with self.app.app_context():
            m = self.module
            esp = m.EspelhoMensal.query.filter_by(usuario_id=uid).one()
            self.assertNotEqual(esp.hash, hash_original)
            self.assertEqual(esp.ciencia_status, "pendente")  # espelho mudou: precisa de nova ciência
            self.assertEqual(m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Reabriu o mês outubro/2026%")).count(), 2)

    def test_espelho_fechado_nao_muda_com_parametros_novos(self):
        rh, uid = self._preparar_outubro()
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token})
        with self.app.app_context():
            m = self.module
            antes = m.EspelhoMensal.query.filter_by(usuario_id=uid).one().dados
            m.db.session.add(m.ParametroJornada(
                vigente_desde=m.date(2026, 11, 1), carga_diaria_min=360, dias_trabalho="0,1,2,3,4",
                tolerancia_marcacao_min=5, tolerancia_diaria_min=10, intervalo_minimo_min=60, interjornada_min=660,
                limite_extras_dia_min=120, extra_util_pct=60, extra_descanso_pct=100, noturno_ativo=False, noturno_pct=20))
            m.db.session.commit()
            self.assertEqual(m.EspelhoMensal.query.filter_by(usuario_id=uid).one().dados, antes)

    def test_exportacao_do_fechamento_para_contabilidade(self):
        import csv as _csv
        import io as _io
        rh, uid = self._preparar_outubro()
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            self.assertEqual(client.get("/admin/fechamento/2026/10/exportar").status_code, 404)  # ainda aberto
            client.post("/admin/fechamento/2026/10/fechar", data={"_csrf_token": token})
            r = client.get("/admin/fechamento/2026/10/exportar?format=csv")
            linhas = list(_csv.reader(_io.StringIO(r.data.decode("utf-8-sig")), delimiter=";"))
            cab = linhas[0]
            func = next(l for l in linhas[1:] if l[cab.index("E-mail")] == "func@example.com")
            self.assertEqual(func[cab.index("Extras 50% (HH:MM)")], "02:00")
            self.assertEqual(func[cab.index("Extras 50% (h)")], "2,0")
            x = client.get("/admin/fechamento/2026/10/exportar?format=excel")
            self.assertEqual(x.status_code, 200)
            self.assertTrue(x.data.startswith(b"PK"))
        with self.app.test_client() as client:
            self.login(client, email="func@example.com")
            self.assertIn(client.get("/admin/fechamento/2026/10/exportar").status_code, (302, 403))

    def test_indicadores_do_painel(self):
        a = self.make_user(email="a@example.com")
        b = self.make_user(email="b@example.com")
        with self.app.app_context():
            m = self.module
            for uid in (a, b):
                m.db.session.get(m.Usuario, uid).data_cadastro = m.datetime(2026, 10, 1)
            pj = m.Usuario(nome="PJ", email="pj@example.com", senha_hash="x", tipo_contrato="PJ",
                           data_cadastro=m.datetime(2026, 10, 1), auth_version=0)
            m.db.session.add(pj)
            # "Hoje" = sex 06/11/2026. Dias úteis do mês até ontem: 03, 04 e 05 (02 é Finados).
            m.db.session.add_all([
                m.RegistroPonto(data="03/11/2026", tipo="Entrada", hora="08:00:00", usuario_id=a),
                m.RegistroPonto(data="03/11/2026", tipo="Saída", hora="17:00:00", usuario_id=a),   # conforme
                m.RegistroPonto(data="04/11/2026", tipo="Entrada", hora="08:00:00", usuario_id=a),  # incompleto
                m.RegistroPonto(data="06/11/2026", tipo="Entrada", hora="08:00:00", usuario_id=a),  # hoje: fora
                m.RegistroPonto(data="04/11/2026", tipo="Entrada", hora="09:00:00", usuario_id=b),
                m.RegistroPonto(data="04/11/2026", tipo="Saída", hora="18:00:00", usuario_id=b),    # conforme
            ])
            # b: atestado no dia 03 (abonado) -> só o dia 05 é falta.
            m.db.session.add(m.Afastamento(usuario_id=b, tipo="atestado", data_inicio=m.date(2026, 11, 3), data_fim=m.date(2026, 11, 3)))
            m.db.session.commit()
            ind = m._indicadores_painel(m.date(2026, 11, 6))
            # a: 03 conforme, 04 incompleto, 05 falta | b: 04 conforme, 05 falta | PJ: sem faltas
            self.assertEqual((ind["conformes"], ind["incompletos"], ind["faltas"]), (2, 1, 2))
            self.assertEqual(ind["mes_referencia"], "novembro")
            self.assertEqual(ind["labels_semana"][-1], "Sex 06/11")
            semana = dict(zip(ind["labels_semana"], ind["dados_semana"]))
            self.assertEqual((semana["Ter 03/11"], semana["Qua 04/11"], semana["Sex 06/11"]), (1, 2, 1))

    def test_migracao_completa_tabela_de_notificacoes_antiga(self):
        from sqlalchemy import inspect, text
        with self.app.app_context():
            m = self.module
            m.db.session.execute(text("DROP TABLE notificacao"))
            # Formato antigo encontrado no Supabase: sem título, tipo e link.
            m.db.session.execute(text(
                "CREATE TABLE notificacao (id INTEGER PRIMARY KEY, usuario_id INTEGER NOT NULL, "
                "mensagem TEXT NOT NULL, lida BOOLEAN, data_criacao DATETIME)"))
            m.db.session.commit()
            with patch.object(m, "_sincronizar_feriados_lib"):
                m._apply_database_migrations()
            cols = {c["name"] for c in inspect(m.db.engine).get_columns("notificacao")}
            self.assertTrue({"titulo", "tipo", "link"} <= cols)

    def test_marcar_todos_os_avisos_como_lidos(self):
        uid = self.make_user()
        with self.app.app_context():
            m = self.module
            for i in range(3):
                m.db.session.add(m.Notificacao(usuario_id=uid, titulo=f"Aviso {i}", mensagem="x", tipo="warning", link="/"))
            m.db.session.commit()
        with self.app.test_client() as client:
            self.login(client)
            self.assertIn("Aviso 2", client.get("/").get_data(as_text=True))
            token = self.csrf(client, "/")
            client.post("/notificacoes/marcar-lidas", data={"_csrf_token": token})
            self.assertNotIn("Aviso 2", client.get("/").get_data(as_text=True))

    # ------------------------------------------------------------------
    # Papéis RH / TI
    # ------------------------------------------------------------------
    ROTAS_RH = ["/admin/historico", "/admin/solicitacoes", "/admin/fragment/historico",
                "/admin/fragment/solicitacoes", "/admin/exportar-afd"]
    ROTAS_TI = ["/admin/logs", "/admin/fragment/logs"]
    ROTAS_GESTAO = ["/admin", "/admin/usuarios", "/admin/fragment/painel", "/admin/fragment/usuarios"]

    def _status_get(self, email, rotas):
        with self.app.test_client() as client:
            self.login(client, email=email)
            return {r: client.get(r).status_code for r in rotas}

    def test_rh_nao_acessa_telas_da_ti(self):
        self.make_user(email="rh@example.com", rh=True)
        status = self._status_get("rh@example.com", self.ROTAS_RH + self.ROTAS_TI + self.ROTAS_GESTAO)
        for r in self.ROTAS_RH + self.ROTAS_GESTAO:
            self.assertEqual(status[r], 200, r)
        for r in self.ROTAS_TI:
            self.assertIn(status[r], (302, 403), r)
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post("/admin/departamentos", data={"_csrf_token": token, "nome": "Hackeado"})
            client.post("/admin/feriados/adicionar", data={"_csrf_token": token, "data": "2026-12-26", "descricao": "X"})
            html = client.get("/admin/fragment/usuarios").get_data(as_text=True)
            painel = client.get("/admin").get_data(as_text=True)
            self.assertNotIn('id="formPapeisUsuario"', painel)
            self.assertIn('id="formSenhaUsuario"', painel)
            self.assertIn("Novo Colaborador", html)
        with self.app.app_context():
            self.assertEqual(self.module.Departamento.query.count(), 0)
            self.assertEqual(self.module.Feriado.query.filter_by(descricao="X").count(), 0)

    def test_ti_nao_opera_ponto_nem_colaboradores(self):
        self.make_user(email="ti@example.com", ti=True)
        alvo_id = self.make_user(email="alvo@example.com")
        status = self._status_get("ti@example.com", self.ROTAS_RH + self.ROTAS_TI + self.ROTAS_GESTAO)
        for r in self.ROTAS_TI + self.ROTAS_GESTAO:
            self.assertEqual(status[r], 200, r)
        for r in self.ROTAS_RH:
            self.assertIn(status[r], (302, 403), r)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            client.post(f"/admin/usuarios/{alvo_id}/senha", data={
                "_csrf_token": token, "nova_senha": "Nova@Senha9", "confirmar_senha": "Nova@Senha9"})
            client.post("/admin/cadastrar_usuario", data={
                "_csrf_token": token, "nome": "X", "email": "x@example.com", "modo_acesso": "senha",
                "senha": "Nova@Senha9", "confirmar_senha": "Nova@Senha9"})
            client.post(f"/admin/excluir-usuario/{alvo_id}", data={"_csrf_token": token})
            client.post("/admin/departamentos", data={"_csrf_token": token, "nome": "TI"})
            painel = client.get("/admin").get_data(as_text=True)
            self.assertIn('id="formPapeisUsuario"', painel)
            self.assertNotIn('id="formSenhaUsuario"', painel)
        with self.app.app_context():
            m = self.module
            alvo = m.db.session.get(m.Usuario, alvo_id)
            self.assertIsNotNone(alvo)
            self.assertTrue(m.check_password_hash(alvo.senha_hash, "Abcdef1@"))
            self.assertIsNone(m.Usuario.query.filter_by(email="x@example.com").first())
            self.assertEqual(m.Departamento.query.filter_by(nome="TI").count(), 1)

    def test_colaborador_nao_acessa_painel(self):
        self.make_user(email="func@example.com")
        status = self._status_get("func@example.com", self.ROTAS_RH + self.ROTAS_TI + self.ROTAS_GESTAO)
        for r, code in status.items():
            self.assertIn(code, (302, 403), r)

    def test_ti_define_papeis_e_rh_nao(self):
        ti_id = self.make_user(email="ti@example.com", ti=True)
        rh_id = self.make_user(email="rh@example.com", rh=True)
        alvo_id = self.make_user(email="alvo@example.com")

        alvo = self.app.test_client()
        self.login(alvo, email="alvo@example.com")

        # RH não consegue se promover a TI nem promover ninguém.
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            token = self.csrf(client, "/admin")
            client.post(f"/admin/usuarios/{rh_id}/papeis", data={"_csrf_token": token, "is_rh": "on", "is_ti": "on"})
            client.post(f"/admin/usuarios/{alvo_id}/papeis", data={"_csrf_token": token, "is_rh": "on"})

        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            client.post(f"/admin/usuarios/{alvo_id}/papeis", data={"_csrf_token": token, "is_rh": "on"})
            # Último TI não pode remover o próprio papel.
            client.post(f"/admin/usuarios/{ti_id}/papeis", data={"_csrf_token": token})

        with self.app.app_context():
            m = self.module
            self.assertFalse(m.db.session.get(m.Usuario, rh_id).is_ti)
            alvo_user = m.db.session.get(m.Usuario, alvo_id)
            self.assertTrue(alvo_user.is_rh)
            self.assertFalse(alvo_user.is_ti)
            self.assertTrue(m.db.session.get(m.Usuario, ti_id).is_ti)
            log = m.LogAuditoria.query.filter(m.LogAuditoria.acao.like("Alterou papéis de%")).one()
            self.assertIn("Colaborador -> RH", log.acao)

        # A sessão aberta do promovido cai para o novo papel valer de imediato.
        self.assertEqual(alvo.get("/", follow_redirects=False).status_code, 302)

    def test_migracao_admin_legado_vira_rh_e_ti(self):
        from sqlalchemy import text
        with self.app.app_context():
            m = self.module
            m.db.session.execute(text("DROP TABLE usuario"))
            m.db.session.execute(text(
                "CREATE TABLE usuario (id INTEGER PRIMARY KEY, nome VARCHAR(100) NOT NULL, "
                "email VARCHAR(100) NOT NULL UNIQUE, senha_hash VARCHAR(200) NOT NULL, is_admin BOOLEAN DEFAULT 0)"
            ))
            m.db.session.execute(text(
                "INSERT INTO usuario (nome, email, senha_hash, is_admin) VALUES "
                "('Admin', 'a@example.com', 'x', 1), ('Func', 'f@example.com', 'x', 0)"
            ))
            m.db.session.commit()
            with patch.object(m, "_sincronizar_feriados_lib"):
                m._apply_database_migrations()
                m._apply_database_migrations()  # idempotente
            linhas = dict(m.db.session.execute(text("SELECT email, is_rh || '/' || is_ti FROM usuario")).all())
            self.assertEqual(linhas, {"a@example.com": "1/1", "f@example.com": "0/0"})


    # ------------------------------------------------------------------
    # Painel em blocos
    # ------------------------------------------------------------------
    def _ids_blocos(self, html):
        """[(id, x, y, w, h)] na ordem em que o painel renderizou."""
        return [(i, int(x), int(y), int(w), int(h)) for i, x, y, w, h in re.findall(
            r'data-bloco="([a-z_]+)"\s+gs-id="[a-z_]+" gs-x="(\d+)" gs-y="(\d+)" gs-w="(\d+)" gs-h="(\d+)"', html)]

    def _post_layout(self, client, token, corpo):
        return client.post("/admin/painel/layout", json=corpo, headers={"X-CSRF-Token": token})

    def test_painel_padrao_por_papel(self):
        self.make_user(email="rh@example.com", rh=True)
        self.make_user(email="ti@example.com", ti=True)
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            blocos = self._ids_blocos(client.get("/admin").get_data(as_text=True))
            self.assertEqual([b[0] for b in blocos], self.module.PAINEL_PADRAO)
            # 4 indicadores lado a lado na primeira linha, atalhos logo abaixo
            self.assertEqual(blocos[:5], [("colaboradores", 0, 0, 3, 2), ("conformes", 3, 0, 3, 2),
                                          ("pendencias", 6, 0, 3, 2), ("solic_qtd", 9, 0, 3, 2),
                                          ("atalhos", 0, 2, 12, 2)])
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            blocos = self._ids_blocos(client.get("/admin/fragment/painel").get_data(as_text=True))
            ids = [b[0] for b in blocos]
            for so_rh in ("solic_qtd", "sem_entrada", "afastados", "solicitacoes", "extras"):
                self.assertNotIn(so_rh, ids)
            self.assertEqual(blocos[:3], [("colaboradores", 0, 0, 4, 2), ("conformes", 4, 0, 4, 2),
                                          ("pendencias", 8, 0, 4, 2)])

    def test_painel_salva_layout_validado_e_restaura(self):
        self.make_user(email="ti@example.com", ti=True)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            token = self.csrf(client, "/admin")
            r = self._post_layout(client, token, {"blocos": [
                {"id": "alertas", "x": 5, "y": 0, "w": 99, "h": 99},   # largura/altura limitadas; x volta p/ caber
                {"id": "extras", "x": 0, "y": 0, "w": 6, "h": 5},      # só RH: descartado
                {"id": "inexistente", "x": 0, "y": 0, "w": 3, "h": 3},
                {"id": "presenca", "x": 2, "y": 20, "w": 1, "h": 1},   # abaixo do mínimo
                {"id": "alertas", "x": 0, "y": 0, "w": 4, "h": 4},     # repetido
                {"id": ["x"], "x": 0},                                  # id inválido
                {"id": "colaboradores"},                                # sem posição: vai para baixo
            ]})
            self.assertEqual(r.status_code, 200)
            esperado = [{"id": "alertas", "x": 0, "y": 0, "w": 12, "h": 20},
                        {"id": "presenca", "x": 2, "y": 20, "w": 3, "h": 3},
                        {"id": "colaboradores", "x": 0, "y": 23, "w": 3, "h": 2}]
            self.assertEqual(r.get_json()["blocos"], esperado)
            blocos = self._ids_blocos(client.get("/admin").get_data(as_text=True))
            self.assertEqual(blocos, [tuple(e.values()) for e in esperado])
            with self.app.app_context():
                cfg = self.module.Configuracao.query.filter(self.module.Configuracao.chave.like("painel:%")).one()
                self.assertEqual(cfg.valor, "al.0.0.12.20,pr.2.20.3.3,co.0.23.3.2")
            # Sem CSRF: recusado
            self.assertEqual(client.post("/admin/painel/layout", json={"restaurar": True}).status_code, 403)
            self._post_layout(client, token, {"restaurar": True})
            self.assertEqual(len(self._ids_blocos(client.get("/admin").get_data(as_text=True))), 9)
            self.assertEqual(self._post_layout(client, token, {"blocos": "x"}).status_code, 400)

    def test_painel_layout_antigo_ou_corrompido_volta_ao_padrao(self):
        uid = self.make_user(email="a@example.com", admin=True)
        with self.app.app_context():
            self.module.db.session.add(self.module.Configuracao(chave=f"painel:{uid}", valor="presenca:8,alertas:4"))
            self.module.db.session.commit()
        with self.app.test_client() as client:
            self.login(client, email="a@example.com")
            self.assertEqual(len(self._ids_blocos(client.get("/admin").get_data(as_text=True))),
                             len(self.module.PAINEL_PADRAO))

    def test_painel_layout_cabe_no_campo(self):
        m = self.module
        uid = self.make_user(email="a@example.com", admin=True)
        with self.app.test_client() as client:
            self.login(client, email="a@example.com")
            token = self.csrf(client, "/admin")
            pior = [{"id": b, "x": 0, "y": 300, "w": 12, "h": 20} for b in m.PAINEL_BLOCOS]
            self.assertEqual(self._post_layout(client, token, {"blocos": pior}).status_code, 200)
        with self.app.app_context():
            self.assertLessEqual(len(m.db.session.get(m.Configuracao, f"painel:{uid}").valor), 255)

    def test_painel_layout_e_por_usuario_e_colaborador_nao_salva(self):
        self.make_user(email="a@example.com", admin=True)
        self.make_user(email="b@example.com", admin=True)
        self.make_user(email="func@example.com")
        with self.app.test_client() as client:
            self.login(client, email="a@example.com")
            token = self.csrf(client, "/admin")
            self._post_layout(client, token, {"blocos": [{"id": "extras", "x": 0, "y": 0, "w": 12, "h": 6}]})
            self.assertEqual(self._ids_blocos(client.get("/admin").get_data(as_text=True)), [("extras", 0, 0, 12, 6)])
        with self.app.test_client() as client:
            self.login(client, email="b@example.com")
            self.assertEqual(len(self._ids_blocos(client.get("/admin").get_data(as_text=True))),
                             len(self.module.PAINEL_PADRAO))
        with self.app.test_client() as client:
            self.login(client, email="func@example.com")
            token = self.csrf(client, "/")
            r = self._post_layout(client, token, {"blocos": []})
            self.assertIn(r.status_code, (302, 403))
        with self.app.app_context():
            self.assertEqual(self.module.Configuracao.query.filter(
                self.module.Configuracao.chave.like("painel:%")).count(), 1)

    def test_painel_blocos_com_dados(self):
        m = self.module
        rh_id = self.make_user(email="rh@example.com", admin=True)
        func_id = self.make_user(email="func@example.com")
        hoje = m.datetime.now(m.ZoneInfo("America/Sao_Paulo")).date()
        with self.app.app_context():
            m.db.session.add(m.Afastamento(usuario_id=func_id, tipo="ferias", data_inicio=hoje,
                                           data_fim=hoje + m.timedelta(days=3)))
            m.db.session.add(m.SolicitacaoCorrecao(data_ponto=hoje.strftime("%d/%m/%Y"), tipo_ponto="Entrada",
                                                   hora_correta="08:00:00", justificativa="Esqueci <b>",
                                                   usuario_id=func_id))
            m.db.session.commit()
            sol_id = m.SolicitacaoCorrecao.query.first().id
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            html = client.get("/admin").get_data(as_text=True)
            self.assertIn("Férias", html)
            self.assertIn("Esqueci &lt;b&gt;", html)
            self.assertIn('name="voltar" value="painel"', html)
            token = self.csrf(client, "/admin")
            r = client.post(f"/admin/solicitacoes/{sol_id}/aprovar", data={"_csrf_token": token, "voltar": "painel"})
            self.assertEqual(r.status_code, 302)
            self.assertTrue(r.headers["Location"].endswith("/admin"))

    # ------------------------------------------------------------------
    # Separação de funções (auditoria de segurança, etapa 1)
    # ------------------------------------------------------------------
    def _post(self, client, path, **data):
        token = self.csrf(client, "/admin")
        return client.post(path, data={"_csrf_token": token, **data})

    def test_rh_nao_troca_senha_nem_exclui_conta_de_rh_ou_ti(self):
        self.make_user(email="rh@example.com", rh=True)
        ti_id = self.make_user(email="ti@example.com", ti=True)
        rh2_id = self.make_user(email="rh2@example.com", rh=True)
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            for alvo in (ti_id, rh2_id):
                self._post(client, f"/admin/usuarios/{alvo}/senha", nova_senha="Nova@Senha9", confirmar_senha="Nova@Senha9")
                self._post(client, f"/admin/excluir-usuario/{alvo}")
        with self.app.app_context():
            m = self.module
            for alvo in (ti_id, rh2_id):
                user = m.db.session.get(m.Usuario, alvo)
                self.assertIsNotNone(user)
                self.assertTrue(m.check_password_hash(user.senha_hash, "Abcdef1@"))

    def test_ti_nao_se_atribui_papel_novo(self):
        ti_id = self.make_user(email="ti@example.com", ti=True)
        with self.app.test_client() as client:
            self.login(client, email="ti@example.com")
            self._post(client, f"/admin/usuarios/{ti_id}/papeis", is_rh="on", is_ti="on")
        with self.app.app_context():
            self.assertFalse(self.module.db.session.get(self.module.Usuario, ti_id).is_rh)

    def test_rh_nao_mexe_no_proprio_ponto(self):
        rh_id = self.make_user(email="rh@example.com", rh=True)
        self.make_user(email="rh2@example.com", rh=True)
        hoje = self.module.datetime.now(self.module.ZoneInfo("America/Sao_Paulo")).date()
        with self.app.app_context():
            m = self.module
            ponto = m.RegistroPonto(data=hoje.strftime("%d/%m/%Y"), tipo="Entrada", hora="08:00:00", usuario_id=rh_id)
            sol = m.SolicitacaoCorrecao(data_ponto=hoje.strftime("%d/%m/%Y"), tipo_ponto="Saída",
                                        hora_correta="22:00:00", justificativa="x", usuario_id=rh_id)
            m.db.session.add_all([ponto, sol])
            m.db.session.commit()
            ponto_id, sol_id = ponto.id, sol.id
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            self._post(client, "/admin/lancar-ponto-manual", usuario_id=str(rh_id),
                       data=hoje.isoformat(), tipo="Saída", hora="22:00")
            self._post(client, f"/admin/excluir-ponto/{ponto_id}")
            self._post(client, f"/admin/solicitacoes/{sol_id}/aprovar")
            self._post(client, "/admin/afastamentos", usuario_id=str(rh_id), tipo="ferias",
                       data_inicio=hoje.isoformat(), data_fim=hoje.isoformat())
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.RegistroPonto.query.filter_by(usuario_id=rh_id).count(), 1)
            self.assertEqual(m.db.session.get(m.SolicitacaoCorrecao, sol_id).status, "Pendente")
            self.assertEqual(m.Afastamento.query.filter_by(usuario_id=rh_id).count(), 0)
        # A outra pessoa do RH pode aprovar.
        with self.app.test_client() as client:
            self.login(client, email="rh2@example.com")
            self._post(client, f"/admin/solicitacoes/{sol_id}/aprovar")
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.db.session.get(m.SolicitacaoCorrecao, sol_id).status, "Aprovada")
            self.assertEqual(m.RegistroPonto.query.filter_by(usuario_id=rh_id).count(), 2)

    def test_solicitacao_respondida_nao_e_reprocessada(self):
        self.make_user(email="rh@example.com", rh=True)
        func_id = self.make_user(email="func@example.com")
        hoje = self.module.datetime.now(self.module.ZoneInfo("America/Sao_Paulo")).date()
        with self.app.app_context():
            m = self.module
            recusada = m.SolicitacaoCorrecao(data_ponto=hoje.strftime("%d/%m/%Y"), tipo_ponto="Entrada",
                                             hora_correta="08:00:00", justificativa="x", usuario_id=func_id)
            pendente = m.SolicitacaoCorrecao(data_ponto=hoje.strftime("%d/%m/%Y"), tipo_ponto="Saída",
                                             hora_correta="17:00:00", justificativa="x", usuario_id=func_id)
            m.db.session.add_all([recusada, pendente])
            m.db.session.commit()
            ids = recusada.id, pendente.id
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            self._post(client, f"/admin/solicitacoes/{ids[0]}/recusar")
            self._post(client, f"/admin/solicitacoes/{ids[0]}/aprovar")
            for _ in range(3):
                self._post(client, f"/admin/solicitacoes/{ids[1]}/aprovar")
        with self.app.app_context():
            m = self.module
            self.assertEqual(m.db.session.get(m.SolicitacaoCorrecao, ids[0]).status, "Recusada")
            self.assertEqual(m.RegistroPonto.query.filter_by(usuario_id=func_id).count(), 1)

    def test_lancamento_manual_valida_data_tipo_e_hora(self):
        self.make_user(email="rh@example.com", rh=True)
        func_id = self.make_user(email="func@example.com")
        hoje = self.module.datetime.now(self.module.ZoneInfo("America/Sao_Paulo")).date()
        with self.app.test_client() as client:
            self.login(client, email="rh@example.com")
            base = {"usuario_id": str(func_id), "data": hoje.isoformat(), "tipo": "Entrada", "hora": "08:00"}
            for invalido in ({"data": hoje.strftime("%d/%m/%Y")}, {"tipo": "Qualquer"}, {"hora": "25:00"}, {"hora": "x"}):
                self._post(client, "/admin/lancar-ponto-manual", **{**base, **invalido})
            with self.app.app_context():
                self.assertEqual(self.module.RegistroPonto.query.count(), 0)
            self._post(client, "/admin/lancar-ponto-manual", **base)
        with self.app.app_context():
            self.assertEqual(self.module.RegistroPonto.query.one().hora, "08:00:00")

    def test_correcao_valida_tipo_e_hora(self):
        self.make_user()
        hoje = self.module.datetime.now(self.module.ZoneInfo("America/Sao_Paulo")).date()
        with self.app.test_client() as client:
            self.login(client)
            token = self.csrf(client, "/solicitar-correcao")
            base = {"_csrf_token": token, "data_ponto": hoje.isoformat(), "justificativa": "x"}
            client.post("/solicitar-correcao", data={**base, "tipo_ponto": "Intervalo", "hora_correta": "08:00"})
            client.post("/solicitar-correcao", data={**base, "tipo_ponto": "Entrada", "hora_correta": "99:99"})
        with self.app.app_context():
            self.assertEqual(self.module.SolicitacaoCorrecao.query.count(), 0)

    def test_troca_obrigatoria_de_senha_bloqueia_o_resto(self):
        self.make_user(needs_reset=True)
        self.make_user(email="livre@example.com")
        with self.app.test_client() as client:
            self.login(client)
            self.assertEqual(client.get("/").location, "/redefinir_senha_forca")
            self.assertEqual(client.get("/meu_historico").location, "/redefinir_senha_forca")
            self.assertEqual(client.get("/redefinir_senha_forca").status_code, 200)
        # Sem a pendência, a rota não troca senha sem a senha atual.
        with self.app.test_client() as client:
            self.login(client, email="livre@example.com")
            token = self.csrf(client, "/")
            r = client.post("/redefinir_senha_forca", data={"_csrf_token": token, "senha": "Outra@Senha9"})
            self.assertEqual(r.location, "/")
        with self.app.app_context():
            m = self.module
            livre = m.Usuario.query.filter_by(email="livre@example.com").one()
            self.assertTrue(m.check_password_hash(livre.senha_hash, "Abcdef1@"))

    # ------------------------------------------------------------------
    # XSS, CSP e push (auditoria de segurança, etapa 2)
    # ------------------------------------------------------------------
    def test_csp_sem_unsafe_inline_e_scripts_com_nonce(self):
        self.make_user(email="admin@example.com", admin=True)
        with self.app.test_client() as client:
            for path in ("/login",):
                r = client.get(path)
                csp = r.headers["Content-Security-Policy"]
                script_src = re.search(r"script-src ([^;]+)", csp).group(1)
                self.assertNotIn("unsafe-inline", script_src)
                self.assertNotIn("https://cdn.jsdelivr.net ", script_src + " ")  # domínio inteiro não
                nonce = re.search(r"'nonce-([^']+)'", script_src).group(1)
                html = r.get_data(as_text=True)
                for tag in re.findall(r"<script\b[^>]*>", html):
                    self.assertTrue(f'nonce="{nonce}"' in tag or "integrity=" in tag, tag)
            self.login(client, "admin@example.com")
            for path in ("/", "/admin", "/meu_historico", "/solicitar-correcao"):
                html = client.get(path).get_data(as_text=True)
                self.assertIsNone(re.search(r"<[^>]+\son[a-z]+\s*=", html), path)
                for tag in re.findall(r"<script\b[^>]*>", html):
                    self.assertTrue("nonce=" in tag or "integrity=" in tag, f"{path}: {tag}")
        # Nonce muda a cada requisição.
        with self.app.test_client() as client:
            a = client.get("/login").headers["Content-Security-Policy"]
            b = client.get("/login").headers["Content-Security-Policy"]
            self.assertNotEqual(a, b)

    def test_nome_malicioso_nao_vira_javascript_nos_fragmentos(self):
        self.make_user(email="admin@example.com", admin=True)
        payload = "x');alert(1);//"
        with self.app.app_context():
            m = self.module
            hoje = m.datetime.now(m.ZoneInfo("America/Sao_Paulo")).date()
            alvo = m.Usuario(nome=payload, email="alvo@example.com", senha_hash="x", email_confirmado=True)
            m.db.session.add(alvo)
            m.db.session.add(m.Departamento(nome=payload))
            m.db.session.flush()
            m.db.session.add(m.Afastamento(usuario_id=alvo.id, tipo="ferias", data_inicio=hoje, data_fim=hoje))
            m.db.session.commit()
        with self.app.test_client() as client:
            self.login(client, "admin@example.com")
            for frag in ("afastamentos", "parametros"):
                html = client.get(f"/admin/fragment/{frag}").get_data(as_text=True)
                self.assertIn("data-confirm=", html, frag)
                self.assertNotIn("confirm('", html, frag)
                self.assertIn("x&#39;);alert(1);//", html, frag)

    def test_push_so_aceita_servicos_conhecidos_e_limita_aparelhos(self):
        uid = self.make_user()
        m = self.module
        validos = ["https://fcm.googleapis.com/fcm/send/a", "https://updates.push.services.mozilla.com/wpush/v2/b",
                   "https://wns2-par02p.notify.windows.com/w/?token=c", "https://web.push.apple.com/d"]
        invalidos = ["https://10.0.0.1/x", "https://evil.example/fcm.googleapis.com", "https://fcm.googleapis.com.evil.example/x",
                     "https://user@fcm.googleapis.com/x", "https://fcm.googleapis.com:8443/x", "http://fcm.googleapis.com/x"]
        for e in validos:
            self.assertTrue(m._endpoint_push_valido(e), e)
        for e in invalidos:
            self.assertFalse(m._endpoint_push_valido(e), e)
        with self.app.test_client() as client:
            self.login(client)
            h = {"X-CSRF-Token": self.csrf(client, "/")}
            with patch.object(m, "VAPID", {"publica": "x", "privada": "y", "claim": "mailto:a@b.c"}):
                self.assertEqual(client.post("/api/push/inscrever", headers=h, json={
                    "endpoint": "https://10.0.0.1/x", "keys": {"p256dh": "k", "auth": "a"}}).status_code, 400)
                for i in range(m.PUSH_MAX_POR_USUARIO + 3):
                    r = client.post("/api/push/inscrever", headers=h, json={
                        "endpoint": f"https://fcm.googleapis.com/fcm/send/{i}", "keys": {"p256dh": "k", "auth": "a"}})
                    self.assertEqual(r.status_code, 200)
        with self.app.app_context():
            restantes = m.PushInscricao.query.filter_by(usuario_id=uid).all()
            self.assertEqual(len(restantes), m.PUSH_MAX_POR_USUARIO)
            self.assertIn(f"/send/{m.PUSH_MAX_POR_USUARIO + 2}", restantes[-1].endpoint if restantes else "")

    def test_push_teste_tem_limite(self):
        self.make_user()
        self.app.config["RATE_LIMIT_ENABLED"] = True
        try:
            with self.app.test_client() as client:
                self.login(client)
                h = {"X-CSRF-Token": self.csrf(client, "/")}
                with patch.object(self.module, "enviar_push", return_value=0):
                    codigos = [client.post("/api/push/teste", headers=h).status_code for _ in range(7)]
            self.assertEqual(codigos[:5], [200] * 5)
            self.assertEqual(codigos[-1], 429)
        finally:
            self.app.config["RATE_LIMIT_ENABLED"] = False

    def test_filtro_de_historico_com_data_invalida_nao_da_500(self):
        self.make_user(email="rh@example.com", rh=True)
        with self.app.test_client() as client:
            self.login(client, "rh@example.com")
            self.assertEqual(client.get("/admin/fragment/historico?data_inicio=x&data_fim=y").status_code, 200)

if __name__ == "__main__":
    unittest.main()


