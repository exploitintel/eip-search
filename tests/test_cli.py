from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from eip_search_v3 import cli
from eip_search_v3.errors import NotFoundError


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def fake_api(monkeypatch, fake_client_class):
    monkeypatch.setattr(cli, "EipClient", fake_client_class)
    return fake_client_class


@pytest.mark.parametrize(
    "arguments",
    [
        ["vuln", "search", "apache", "--severity", "HIGH", "--cisa-kev", "-n", "1"],
        ["vuln", "show", "CVE-2026-1000", "--all", "--section-limit", "2"],
        ["vuln", "nuclei", "CVE-2026-1000"],
        ["exploit", "search", "CVE-2026-1000", "--association", "linked", "-n", "1"],
        ["exploit", "show", "123"],
        ["exploit", "analysis", "123"],
        ["exploit", "files", "123"],
        ["exploit", "view", "123", "poc.py"],
        ["code", "exec(", "--source", "repository-inventory", "-n", "1"],
        ["lab", "search", "CVE-2026", "--analysis", "available", "--include-analysis"],
        ["vendor", "Example"],
        ["product", "--vendor", "Example", "Server"],
        ["ecosystem", "PyPI"],
        ["package", "--ecosystem", "PyPI", "example"],
        ["cwe", "list", "injection"],
        ["cwe", "show", "CWE-78"],
        ["author", "list", "owner", "--source", "github", "--role", "owner"],
        ["author", "show", "789"],
        ["author", "exploits", "789"],
        ["artifact", "artifact-1"],
        ["stats"],
        ["stats", "--trends", "all"],
        ["doctor"],
    ],
)
def test_human_command_families(runner: CliRunner, arguments: list[str]) -> None:
    result = runner.invoke(cli.app, ["--no-color", *arguments])
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


def test_binary_and_stix_commands(runner: CliRunner, tmp_path) -> None:
    result = runner.invoke(cli.app, ["exploit", "download", "123", "-o", str(tmp_path / "poc.zip")])
    assert result.exit_code == 0
    assert "Archive password: eip" in result.output
    assert "not extracted" in result.output

    result = runner.invoke(cli.app, ["lab", "screenshot", "456", "-o", str(tmp_path / "lab.png")])
    assert result.exit_code == 0

    result = runner.invoke(cli.app, ["stix", "vuln", "CVE-2026-1000"])
    assert json.loads(result.output)["type"] == "bundle"
    output = tmp_path / "exploit.json"
    result = runner.invoke(cli.app, ["stix", "exploit", "123", "-o", str(output)])
    assert result.exit_code == 0
    assert json.loads(output.read_text())["type"] == "bundle"
    result = runner.invoke(cli.app, ["stix", "exploit", "123", "-o", str(output)])
    assert result.exit_code == 7
    result = runner.invoke(cli.app, ["stix", "exploit", "123", "-o", str(output), "--force"])
    assert result.exit_code == 0

    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("occupied")
    result = runner.invoke(
        cli.app, ["stix", "exploit", "123", "-o", str(blocked_parent / "bundle.json")]
    )
    assert result.exit_code == 7
    assert "Traceback" not in result.output


def test_json_is_valid_and_uncontaminated(runner: CliRunner) -> None:
    result = runner.invoke(cli.app, ["vuln", "search", "apache", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["next_cursor"] == "opaque-cursor"
    assert "Vulnerability search" not in result.output


def test_parameters_are_forwarded_without_local_reordering(runner: CliRunner, fake_api) -> None:
    result = runner.invoke(
        cli.app,
        [
            "exploit",
            "search",
            "term",
            "--source",
            "exploitdb",
            "--catalog-kind",
            "exploitdb-exploit",
            "--association",
            "unlinked",
            "--language",
            "Python",
            "--source-date-from",
            "2025-01-01",
            "--source-date-to",
            "2026-01-01",
            "--author-id",
            "789",
            "--cursor",
            "opaque-value",
            "--limit",
            "5",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    call = fake_api.instances[-1].calls[-1]
    assert call[0] == "pocs"
    assert call[1] == [
        ("q", "term"),
        ("source", "exploitdb"),
        ("catalog_kind", "exploitdb-exploit"),
        ("association", "unlinked"),
        ("language", "Python"),
        ("source_date_from", "2025-01-01"),
        ("source_date_to", "2026-01-01"),
        ("author_id", 789),
        ("limit", 5),
        ("cursor", "opaque-value"),
    ]


def test_code_search_scope_is_forwarded_without_client_side_derivation(
    runner: CliRunner, fake_api
) -> None:
    result = runner.invoke(
        cli.app,
        [
            "code",
            "subprocess run",
            "--vulnerability",
            "  ghsa-example  ",
            "--source",
            "repository-inventory",
            "--limit",
            "5",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert fake_api.instances[-1].calls[-1] == (
        "code",
        {
            "q": "subprocess run",
            "limit": 5,
            "source": "repository-inventory",
            "vulnerability_id": "ghsa-example",
        },
    )

    result = runner.invoke(cli.app, ["code", "exec call", "--public-id", "123", "--json"])
    assert result.exit_code == 0, result.output
    assert fake_api.instances[-1].calls[-1] == (
        "code",
        {"q": "exec call", "limit": 25, "public_id": 123},
    )


@pytest.mark.parametrize("query", ["变量", "привет", "１２３"])
def test_code_search_accepts_unicode_word_terms(runner: CliRunner, fake_api, query: str) -> None:
    result = runner.invoke(cli.app, ["code", query, "--json"])
    assert result.exit_code == 0, result.output
    assert fake_api.instances[-1].calls[-1] == (
        "code",
        {"q": query, "limit": 25},
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["vuln", "search", "--package", "django"],
        [
            "exploit",
            "search",
            "--source-date-from",
            "2026-01-02",
            "--source-date-to",
            "2026-01-01",
        ],
        ["exploit", "search", "--source-date-from", "yesterday"],
        ["code", "x"],
        ["code", "x" * 201],
        ["code", "!!"],
        ["code", "  "],
        ["code", "exec call", "--public-id", "123", "--vulnerability", "CVE-2026-1"],
        ["code", "exec call", "--vulnerability", "   "],
        ["code", "exec call", "--vulnerability", "CVE-2026-\u202e1234"],
        ["code", "exec call", "--vulnerability", "CVE-2026-\ud800"],
        ["author", "list", "--role", "reviewer"],
        ["vuln", "show", "CVE-2026-1000", "--section", "made-up"],
        ["vuln", "show", "CVE-2026-1000", "--section", "pocs", "--all"],
        ["vuln", "show", "CVE-123"],
        ["exploit", "search", "--author-id", "9000000000000001"],
        ["author", "show", "0"],
    ],
)
def test_invalid_input_is_rejected(runner: CliRunner, arguments: list[str]) -> None:
    result = runner.invoke(cli.app, arguments)
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_api_errors_use_stable_exit_and_stderr(runner: CliRunner, fake_api, monkeypatch) -> None:
    def missing(_self, _identifier):
        raise NotFoundError("record not found")

    monkeypatch.setattr(fake_api, "vulnerability", missing)
    result = runner.invoke(cli.app, ["vuln", "show", "CVE-2026-9999"])
    assert result.exit_code == 3
    assert "record not found" in result.output
    assert "Traceback" not in result.output


def test_doctor_fails_when_subsystem_is_not_ready(runner: CliRunner, fake_api, monkeypatch) -> None:
    monkeypatch.setattr(
        fake_api,
        "readiness",
        lambda _self: {"status": "ready", "code_search_status": "unavailable"},
    )
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 4


def test_bare_argument_routing() -> None:
    assert cli._route_bare_argument(["CVE-2024-3400"]) == [
        "vuln",
        "show",
        "CVE-2024-3400",
    ]
    assert cli._route_bare_argument(["--no-color", "apache"]) == [
        "--no-color",
        "vuln",
        "search",
        "apache",
    ]
    assert cli._route_bare_argument(["--api-base-url", "https://x", "stats"]) == [
        "--api-base-url",
        "https://x",
        "stats",
    ]
    assert cli._route_bare_argument(["CVE-2024"]) == ["vuln", "search", "CVE-2024"]


def test_single_trend_json_contains_only_the_selected_series(runner: CliRunner) -> None:
    result = runner.invoke(cli.app, ["stats", "--trends", "cwe", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert set(payload["trends"]) == {"as_of", "cve_weaknesses"}


def test_entrypoint_contains_unexpected_failures(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "app", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(cli.sys, "argv", ["eip-search", "doctor"])
    with pytest.raises(SystemExit) as raised:
        cli.entrypoint()
    captured = capsys.readouterr()
    assert raised.value.code == 1
    assert "unexpected internal error" in captured.err
    assert "boom" not in captured.err


def test_version_and_help(runner: CliRunner) -> None:
    assert runner.invoke(cli.app, ["--version"]).output.startswith("eip-search ")
    help_result = runner.invoke(cli.app, ["--help"])
    assert help_result.exit_code == 0
    assert help_result.output.startswith(
        "EIP // EXPLOIT INTEL\nVulnerability and exploit intelligence\n"
    )
    assert "Examples:" in help_result.output
    assert "eip-search apache" in help_result.output
    assert "eip-search CVE-2024-3400" in help_result.output
    assert "doctor     Check API and code-search readiness." in help_result.output
    command_order = [
        "vuln",
        "exploit",
        "code",
        "lab",
        "vendor",
        "product",
        "ecosystem",
        "package",
        "cwe",
        "author",
        "artifact",
        "stats",
        "doctor",
        "stix",
    ]
    positions = [help_result.output.index(f"\n  {name}") for name in command_order]
    assert positions == sorted(positions)

    bare_result = runner.invoke(cli.app, [])
    assert bare_result.exit_code == 0
    assert "EIP // EXPLOIT INTEL" in bare_result.output


@pytest.mark.parametrize(
    "group, guidance",
    [
        ("vuln", "eip-search vuln search apache"),
        ("exploit", "eip-search exploit search CVE-2024-3400"),
        ("lab", "eip-search lab search CVE-2024 --kind compose"),
        ("cwe", "eip-search cwe list injection"),
        ("author", "eip-search author list exploitintel --source github"),
        ("stix", "eip-search stix vuln CVE-2024-3400 --mapping v2"),
    ],
)
def test_command_groups_without_subcommands_show_help(
    runner: CliRunner, fake_api, group: str, guidance: str
) -> None:
    result = runner.invoke(cli.app, [group])
    assert result.exit_code == 0
    assert f"Usage: eip-search {group}" in result.output
    assert "Examples:" in result.output
    assert guidance in " ".join(result.output.split())
    assert fake_api.instances == []


def test_public_command_tree_has_no_single_action_groups() -> None:
    root = get_command(cli.app)
    expected_groups = {
        "vuln": {"search", "show", "nuclei"},
        "exploit": {"search", "show", "analysis", "files", "view", "download"},
        "lab": {"search", "screenshot"},
        "cwe": {"list", "show"},
        "author": {"list", "show", "exploits"},
        "stix": {"vuln", "exploit"},
    }
    expected_commands = {
        *expected_groups,
        "code",
        "vendor",
        "product",
        "ecosystem",
        "package",
        "artifact",
        "stats",
        "doctor",
    }

    assert set(root.commands) == expected_commands
    for name, command in root.commands.items():
        assert set(getattr(command, "commands", {})) == expected_groups.get(name, set())


def test_every_runtime_help_example_parses_and_executes(
    runner: CliRunner, monkeypatch, tmp_path
) -> None:
    examples: list[list[str]] = []

    def inspect(command, path: tuple[str, ...]) -> None:
        command_path = " ".join(path)
        command_examples = [
            f"eip-search {line.partition('eip-search ')[2].strip()}"
            for line in command.help.splitlines()
            if "eip-search " in line
        ]
        assert command_examples, f"{command_path} has no example"

        result = runner.invoke(cli.app, [*path[1:], "--help"])
        assert result.exit_code == 0, result.output
        rendered_help = " ".join(result.output.split())
        for example in command_examples:
            arguments = shlex.split(example)
            assert arguments[0] == "eip-search"
            examples.append(arguments[1:])
            assert example in rendered_help

        children = getattr(command, "commands", {})
        if children:
            for name, child in children.items():
                inspect(child, (*path, name))
            return
        assert f"Example: {command_path}" in command.help

    inspect(get_command(cli.app), ("eip-search",))
    monkeypatch.chdir(tmp_path)
    for arguments in examples:
        result = runner.invoke(cli.app, cli._route_bare_argument(arguments))
        assert result.exit_code == 0, f"{arguments!r}: {result.output}"


@pytest.mark.parametrize("document", [Path("README.md"), Path("docs/user-guide.md")])
def test_documented_cli_examples_parse_and_execute(
    runner: CliRunner, document: Path, monkeypatch, tmp_path
) -> None:
    commands = [
        line.strip()
        for line in document.read_text().splitlines()
        if line.strip().startswith("eip-search ")
        and "--show-completion" not in line
        and "--install-completion" not in line
    ]
    assert commands

    monkeypatch.chdir(tmp_path)
    for command in commands:
        arguments = shlex.split(command)[1:]
        if "|" in arguments:
            arguments = arguments[: arguments.index("|")]
        arguments = [argument for argument in arguments if not argument.startswith(">")]
        result = runner.invoke(cli.app, cli._route_bare_argument(arguments))
        assert result.exit_code == 0, f"{document}:{command}: {result.output}"


@pytest.mark.parametrize("command", ["code", "product", "package", "artifact"])
def test_flat_commands_without_required_input_show_help(
    runner: CliRunner, fake_api, command: str
) -> None:
    result = runner.invoke(cli.app, [command])
    assert result.exit_code == 0
    assert f"Usage: eip-search {command}" in result.output
    assert f"Example: eip-search {command}" in result.output
    assert fake_api.instances == []


@pytest.mark.parametrize(
    "arguments, expected",
    [
        (["product", "Windows"], "Missing option '--vendor'"),
        (["package", "Django"], "Missing option '--ecosystem'"),
    ],
)
def test_flat_commands_explain_missing_required_filters(
    runner: CliRunner, arguments: list[str], expected: str
) -> None:
    result = runner.invoke(cli.app, arguments)
    assert result.exit_code == 2
    assert f"Usage: eip-search {arguments[0]}" in result.output
    assert expected in result.output
    assert f"eip-search {arguments[0]} --help" in result.output


def test_missing_required_argument_remains_a_usage_error(runner: CliRunner) -> None:
    result = runner.invoke(cli.app, ["exploit", "view", "123"])
    assert result.exit_code == 2
    assert "Missing argument 'PATH'" in result.output
    assert "exploit view --help" in result.output


def test_help_does_not_require_valid_runtime_configuration(
    runner: CliRunner, fake_api, monkeypatch
) -> None:
    monkeypatch.setenv("EIP_API_BASE_URL", "not-a-url")

    for arguments in (
        [],
        ["vuln"],
        ["vuln", "--help"],
        ["code"],
        ["code", "--help"],
        ["exploit", "view", "--help"],
    ):
        result = runner.invoke(cli.app, arguments)
        assert result.exit_code == 0, result.output
        assert "Usage:" in result.output
        assert "API base URL" not in result.output

    assert fake_api.instances == []


def test_entire_help_tree_is_described() -> None:
    missing: list[str] = []

    def inspect(command, path: tuple[str, ...]) -> None:
        command_path = " ".join(path)
        if not command.help:
            missing.append(f"{command_path}: command help")
        for parameter in command.params:
            if not parameter.help:
                missing.append(f"{command_path}: {parameter.name}")
        for name, child in getattr(command, "commands", {}).items():
            inspect(child, (*path, name))

    inspect(get_command(cli.app), ("eip-search",))
    assert missing == []


def test_json_output_escapes_unicode_terminal_controls(capsys) -> None:
    payload = {"title": "safe\u202eexe.txt", "author": "Jos\u00e9"}
    cli._json(payload)
    output = capsys.readouterr().out
    assert "\u202e" not in output
    assert "\\u202e" in output
    assert "\\u00e9" in output
    assert json.loads(output) == payload


def test_invalid_api_base_url_is_a_clean_input_error(runner: CliRunner) -> None:
    result = runner.invoke(cli.app, ["--api-base-url", "https://example.com:bad", "doctor"])
    assert result.exit_code == 2
    assert "Invalid API base URL" in result.output
    assert "Traceback" not in result.output
