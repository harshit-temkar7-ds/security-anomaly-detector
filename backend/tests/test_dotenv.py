import os

from app.config import load_backend_dotenv


def test_backend_dotenv_loads_missing_values_without_overriding_environment(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SAD_TEST_DOTENV_FROM_FILE=file-value\nSAD_TEST_DOTENV_PRECEDENCE=file-value\n",
                        encoding="utf-8")
    monkeypatch.delenv("SAD_TEST_DOTENV_FROM_FILE", raising=False)
    monkeypatch.setenv("SAD_TEST_DOTENV_PRECEDENCE", "environment-value")

    load_backend_dotenv(env_file)

    assert os.environ["SAD_TEST_DOTENV_FROM_FILE"] == "file-value"
    assert os.environ["SAD_TEST_DOTENV_PRECEDENCE"] == "environment-value"
