import json
import os
from argparse import Namespace

import pytest

from darkbatch.settlement import ironwood_pczt


def test_private_artifacts_are_created_exclusively_and_not_overwritten(tmp_path):
    target = tmp_path / "private.json"
    ironwood_pczt._write_private_json(target, {"secret": "viewing-data"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"secret": "viewing-data"}
    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        ironwood_pczt._write_private_json(target, {"secret": "changed"})
    # POSIX CI enforces owner-only permissions. Windows ACL semantics are different.
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_sign_command_keeps_spending_key_out_of_cli_args_and_stdout(tmp_path, monkeypatch, capsys):
    source = tmp_path / "unsigned.json"
    source.write_text(json.dumps({"pczt_hex": "aabb"}), encoding="utf-8")
    target = tmp_path / "signed.json"
    spending_key = "12" * 32
    observed = {}

    monkeypatch.setattr(ironwood_pczt.getpass, "getpass", lambda prompt: spending_key)

    def fake_run(command, request, timeout_seconds=1800):
        observed["command"] = command
        observed["request"] = request
        return {
            "status": "PARTICIPANT_SIGNATURE_ADDED",
            "signed_nullifier_hex": "34" * 32,
            "action_index": 1,
            "sighash_hex": "56" * 32,
            "pczt_hex": "ccdd",
            "broadcast": False,
        }

    monkeypatch.setattr(ironwood_pczt, "_run_rust", fake_run)
    result = ironwood_pczt.command_sign(Namespace(
        pczt=str(source),
        nullifier="34" * 32,
        sighash="56" * 32,
        out=str(target),
    ))

    captured = capsys.readouterr()
    assert result == 0
    assert observed["command"] == "sign-ironwood-pczt-stdin"
    assert observed["request"]["spending_key_hex"] == spending_key
    assert spending_key not in captured.out
    assert spending_key not in captured.err
    assert spending_key not in target.read_text(encoding="utf-8")
    assert json.loads(target.read_text(encoding="utf-8"))["pczt_hex"] == "ccdd"


def test_create_requires_an_unsigned_official_pczt_and_does_not_overwrite(tmp_path, monkeypatch):
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps({"network": "testnet"}), encoding="utf-8")
    target = tmp_path / "unsigned-pczt.json"
    monkeypatch.setattr(ironwood_pczt, "_run_rust", lambda *args, **kwargs: {
        "status": "PCZT_READY_FOR_REVIEW_AND_PARTICIPANT_SIGNATURES",
        "network": "testnet",
        "transaction_version": 6,
        "consensus_branch_id": "0x37a5165b",
        "input_value_zat": 100_000,
        "output_value_zat": 90_000,
        "fee_zat": 10_000,
        "input_action_indices": [{"input_id": "in1", "action_index": 0}],
        "sighash_hex": "56" * 32,
        "pczt_hex": "aabbccdd",
        "broadcast": False,
    })
    assert ironwood_pczt.command_create(Namespace(request=str(request_path), out=str(target))) == 0
    result = json.loads(target.read_text(encoding="utf-8"))
    assert result["status"] == "PCZT_READY_FOR_REVIEW_AND_PARTICIPANT_SIGNATURES"
    assert result["broadcast"] is False
    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        ironwood_pczt._write_private_json(target, result)



def test_combine_requires_signed_pczt_status_and_saves_only_combined_copy(tmp_path, monkeypatch):
    first = tmp_path / "signed-a.json"
    second = tmp_path / "signed-b.json"
    first.write_text(json.dumps({"pczt_hex": "aabb"}), encoding="utf-8")
    second.write_text(json.dumps({"pczt_hex": "ccdd"}), encoding="utf-8")
    target = tmp_path / "combined.json"
    observed = {}

    def fake_run(command, request, timeout_seconds=1800):
        observed["command"] = command
        observed["request"] = request
        return {
            "status": "PCZT_COMBINED_AND_READY_FOR_FINALIZATION",
            "input_count": 2,
            "participant_pczt_count": 2,
            "sighash_hex": "56" * 32,
            "pczt_hex": "eeff",
            "broadcast": False,
        }

    monkeypatch.setattr(ironwood_pczt, "_run_rust", fake_run)
    assert ironwood_pczt.command_combine(Namespace(
        pczts=[str(first), str(second)],
        nullifiers=("11" * 32) + "," + ("22" * 32),
        out=str(target),
    )) == 0

    assert observed["command"] == "combine-ironwood-pczts-stdin"
    assert observed["request"]["pczt_hexes"] == ["aabb", "ccdd"]
    assert len(observed["request"]["required_nullifiers_hex"]) == 2
    result = json.loads(target.read_text(encoding="utf-8"))
    assert result["pczt_hex"] == "eeff"
    assert result["broadcast"] is False


def test_finalize_rejects_wrong_status_before_writing_raw_transaction(tmp_path, monkeypatch):
    request_path = tmp_path / "finalize.json"
    request_path.write_text(json.dumps({"network": "testnet"}), encoding="utf-8")
    target = tmp_path / "raw-tx.json"
    monkeypatch.setattr(ironwood_pczt, "_run_rust", lambda *args, **kwargs: {
        "status": "PROOF_FAILED",
        "raw_tx_hex": "00",
        "txid": "11" * 32,
        "broadcast": False,
    })
    with pytest.raises(RuntimeError, match="did not return"):
        ironwood_pczt.command_finalize(Namespace(
            request=str(request_path), out=str(target), timeout=30,
        ))
    assert not target.exists()
