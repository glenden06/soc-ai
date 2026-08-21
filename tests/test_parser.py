"""Unit tests for the ingestion module."""

from formats import apache, detect_format, jsonl, ssh, winevent


def test_detect_format_by_filename():
    assert detect_format("auth.log") == "ssh"
    assert detect_format("access.log") == "apache"
    assert detect_format("winevent.xml") == "winevent"
    assert detect_format("firewall.jsonl") == "json"


def test_ssh_failed_password():
    line = ("Aug 20 09:14:11 srv-web01 sshd[2455]: Failed password for invalid user "
            "admin from 45.83.64.12 port 40122 ssh2")
    event = ssh.parse(line)
    assert event["action"] == "auth_failure"
    assert event["source_ip"] == "45.83.64.12"
    assert event["user"] == "admin"
    assert event["source_type"] == "ssh"
    assert event["timestamp"].startswith(f"{event['timestamp'][:4]}-08-20T09:14:11")


def test_ssh_accepted_root():
    line = "Aug 20 09:22:47 srv-db02 sshd[3120]: Accepted password for root from 203.0.113.77 port 43122 ssh2"
    event = ssh.parse(line)
    assert event["action"] == "auth_success"
    assert event["user"] == "root"


def test_ssh_ignores_unrelated_lines():
    assert ssh.parse("Aug 20 09:00:00 srv-web01 CRON[900]: session opened") is None
    assert ssh.parse("") is None


def test_apache_combined_format():
    line = ('45.83.64.12 - - [20/Aug/2026:09:17:02 +0200] "GET /p.php?id=1%20UNION%20SELECT%201 '
            'HTTP/1.1" 500 431 "-" "Mozilla/5.0"')
    event = apache.parse(line)
    assert event["source_ip"] == "45.83.64.12"
    assert event["extra"]["status"] == 500
    assert "union select" in event["extra"]["path_decoded"].lower()


def test_winevent_extracts_event_id_and_object():
    line = ('<Event><System><EventID>4663</EventID>'
            '<TimeCreated SystemTime="2026-08-20T08:15:02.900Z"/><Computer>SRV01</Computer></System>'
            '<EventData><Data Name="SubjectUserName">j.martin</Data>'
            '<Data Name="ObjectName">\\REGISTRY\\MACHINE\\SAM\\SAM</Data></EventData></Event>')
    event = winevent.parse(line)
    assert event["extra"]["event_id"] == "4663"
    assert event["user"] == "j.martin"
    assert "SAM" in event["extra"]["object_name"]


def test_jsonl_normalises_aliases():
    event = jsonl.parse('{"timestamp":"2026-08-20T09:50:01+00:00","src_ip":"1.2.3.4","action":"port_probe"}')
    assert event["source_ip"] == "1.2.3.4"
    assert event["action"] == "port_probe"
    assert jsonl.parse("not json") is None


def test_parse_file_and_offsets(tmp_path, db_path):
    import parser as ingest

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Aug 20 09:14:11 h sshd[1]: Failed password for invalid user a from 1.1.1.1 port 1 ssh2\n"
    )
    events, offset = ingest.parse_file(str(log_file))
    assert len(events) == 1
    assert offset > 0

    events, _ = ingest.parse_file(str(log_file), start_offset=offset)
    assert events == []
