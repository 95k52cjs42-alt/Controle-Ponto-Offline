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

    def make_user(self, email="user@example.com", admin=False, needs_reset=False):
        with self.app.app_context():
            user = self.module.Usuario(
                nome="Usuário <Teste>",
                email=email,
                senha_hash=generate_password_hash("Abcdef1@", method="scrypt"),
                email_confirmado=True,
                is_admin=admin,
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
    def test_public_registration_never_promotes_first_user(self):
        with self.app.app_context():
            self.module._set_config("email_confirmacao_obrigatoria", "false")
            self.module.db.session.commit()
        with self.app.test_client() as client:
            token = self.csrf(client, "/cadastro")
            with patch.object(self.module, "verificar_dominio_email", return_value=True):
                response = client.post("/cadastro", data={
                    "_csrf_token": token,
                    "nome": "Primeiro",
                    "email": "first@example.com",
                    "senha": "Abcdef1@",
                })
            self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            user = self.module.Usuario.query.filter_by(email="first@example.com").first()
            self.assertIsNotNone(user)
            self.assertFalse(user.is_admin)

    def test_confirmation_requires_post_and_cannot_replay(self):
        with self.app.app_context():
            raw, _row = self.module.issue_security_token(
                None,
                self.module.SecurityToken.PURPOSE_CONFIRM,
                1800,
                email="confirm@example.com",
                nome="Confirmado",
                senha_hash=generate_password_hash("Abcdef1@", method="scrypt"),
            )
        with self.app.test_client() as client:
            response = client.get(f"/confirm_email/{raw}")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.module.Usuario.query.count(), 0)
            token = self.csrf(client, f"/confirm_email/{raw}")
            response = client.post(f"/confirm_email/{raw}", data={"_csrf_token": token})
            self.assertEqual(response.status_code, 302)
            response = client.post(f"/confirm_email/{raw}", data={"_csrf_token": token})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/login")
        with self.app.app_context():
            self.assertEqual(self.module.Usuario.query.filter_by(email="confirm@example.com").count(), 1)

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
        with self.app.app_context():
            self.module._set_config("email_confirmacao_obrigatoria", "true")
            self.module.db.session.commit()

        with self.app.test_client() as client:
            token = self.csrf(client, "/cadastro")
            with patch.object(self.module, "verificar_dominio_email", return_value=True), \
                 patch.object(self.module, "_send_email", return_value=True) as mock_send:
                response = client.post("/cadastro", data={
                    "_csrf_token": token,
                    "nome": "Hacker <script>alert(1)</script>",
                    "email": "hacker@example.com",
                    "senha": "Abcdef1@",
                })
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, "/login")
                mock_send.assert_called_once()
                body = mock_send.call_args[0][2]
                self.assertNotIn("<script>", body)
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)

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


if __name__ == "__main__":
    unittest.main()


