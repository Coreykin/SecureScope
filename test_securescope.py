import csv
import json
import tempfile
import unittest
from pathlib import Path
from securescope import scan, summary, write_json, write_html, write_csv

class SecureScopeTests(unittest.TestCase):
    def scan_source(self, text, filename='app.py'):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/filename).write_text(text, encoding='utf-8')
            return scan(root)

    def ids(self, text):
        return {f.rule_id for f in self.scan_source(text)}

    def test_debug_assignment(self):
        self.assertEqual(self.ids('DEBUG = True'), {'SS001'})

    def test_debug_subscript(self):
        self.assertEqual(self.ids('app.config["DEBUG"] = True'), {'SS001'})

    def test_multiline_debug(self):
        self.assertEqual(self.ids('app.run(\n debug=True\n)'), {'SS001'})

    def test_secret_subscript_and_short_literal(self):
        self.assertEqual(self.ids('app.config["SECRET_KEY"] = "abc"'), {'SS002'})

    def test_config_update(self):
        self.assertEqual(self.ids('app.config.update(\n SECRET_KEY="abcdef",\n SESSION_COOKIE_SECURE=False,\n DEBUG=True\n)'), {'SS001','SS002','SS003'})

    def test_config_dictionary_update(self):
        self.assertEqual(self.ids('app.config.update({"SESSION_COOKIE_HTTPONLY": False})'), {'SS003'})

    def test_cookies_report_separate_locations(self):
        results=self.scan_source('app.config["SESSION_COOKIE_SECURE"]=False\napp.config["SESSION_COOKIE_HTTPONLY"]=False')
        self.assertEqual([f.line for f in results], [1,2])
        self.assertEqual([f.rule_id for f in results], ['SS003','SS003'])

    def test_http_endpoint(self):
        self.assertEqual(self.ids('url="http://example.com"'), {'SS004'})

    def test_loopback_host_exact_match(self):
        self.assertEqual(self.ids('url="http://localhost.evil.example"'), {'SS004'})
        self.assertEqual(self.ids('url="http://localhost:8000"\nurl="http://[::1]:8000"'), set())

    def test_multiline_shell(self):
        self.assertEqual(self.ids('subprocess.run(\n command,\n shell=True\n)'), {'SS005'})

    def test_dynamic_execution(self):
        self.assertEqual(self.ids('eval(user_input)\nexec(user_input)'), {'SS006'})

    def test_wildcard_origins(self):
        self.assertEqual(self.ids('CORS(app, origins="*")'), {'SS007'})

    def test_wildcard_resources_origins(self):
        self.assertEqual(self.ids('CORS(app, resources={r"/*": {"origins": "*"}})'), {'SS007'})

    def test_wildcard_route_trusted_origin(self):
        self.assertEqual(self.ids('CORS(app, resources={r"/*": {"origins": "https://trusted.example"}})'), set())

    def test_request_reads(self):
        self.assertEqual(self.ids('body=request.get_data()\nbody=request.data'), {'SS008'})

    def test_comments_and_documentation(self):
        self.assertEqual(self.ids('# DEBUG=True\n"""eval(user_input) and DEBUG=True"""'), set())

    def test_safe_configuration(self):
        text='app.config.update(SECRET_KEY=os.environ["SECRET_KEY"], SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, DEBUG=False)\nsubprocess.run(["echo", value], shell=False)\nurl="https://example.com"'
        self.assertEqual(self.ids(text), set())

    def test_all_reports_withhold_secrets_on_other_rule_line(self):
        secret='secret-value-123'
        findings=self.scan_source('app.config.update(SECRET_KEY="'+secret+'", DEBUG=True)')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for function, suffix in [(write_json,'json'),(write_html,'html'),(write_csv,'csv')]:
                output=root/('report.'+suffix)
                function(output, Path('sample_app'), findings)
                self.assertNotIn(secret, output.read_text())
            payload=json.loads((root/'report.json').read_text())
            self.assertEqual(payload['summary']['total_findings'],2)
            with (root/'report.csv').open() as stream:
                self.assertEqual(len(list(csv.DictReader(stream))),2)

    def test_html_escapes_filename(self):
        findings=self.scan_source('DEBUG=True', '<script>.py')
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'report.html'
            write_html(output,Path('sample_app'),findings)
            self.assertIn('&lt;script&gt;.py',output.read_text())
            self.assertNotIn('<script>',output.read_text())

    def test_csv_formula_filename(self):
        findings=self.scan_source('DEBUG=True', '=danger.py')
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'report.csv'
            write_csv(output,Path('sample_app'),findings)
            with output.open() as stream:
                self.assertEqual(next(csv.DictReader(stream))['file'], "'=danger.py")

    def test_skips_venv_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'.venv').mkdir()
            (root/'.venv'/'app.py').write_text('DEBUG=True')
            (root/'link.py').symlink_to(root/'.venv'/'app.py')
            self.assertEqual(scan(root),[])

    def test_dotenv(self):
        findings=self.scan_source('api_key="abcdef123456"', '.env')
        self.assertEqual({f.rule_id for f in findings},{'SS002'})

    def test_parse_failure_is_explicit(self):
        with self.assertRaisesRegex(ValueError,'Cannot parse app.py'):
            self.scan_source('def broken(')

    def test_summary(self):
        result=summary(self.scan_source('exec(user_input)'))
        self.assertEqual(result['total_findings'],1)
        self.assertEqual(result['by_stride']['Tampering'],1)

if __name__=='__main__':
    unittest.main()
