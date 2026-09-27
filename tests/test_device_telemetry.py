import os
import tempfile

from server.database import init_db
from server.models import DeviceModel, DeviceTelemetryModel


def test_device_telemetry_upsert_and_read():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(path)
        DeviceModel.register_or_update("agent_telemetry", "test-host", "Linux", "127.0.0.1", path)
        DeviceTelemetryModel.upsert("agent_telemetry", "system", {"hostname": "test-host"}, db_path=path)
        DeviceTelemetryModel.upsert("agent_telemetry", "processes", [{"pid": 1, "name": "init"}], db_path=path)

        system = DeviceTelemetryModel.get("agent_telemetry", "system", path)
        processes = DeviceTelemetryModel.get("agent_telemetry", "processes", path)
        assert system["data"]["hostname"] == "test-host"
        assert processes["data"][0]["pid"] == 1
        assert {x["category"] for x in DeviceTelemetryModel.list_for_agent("agent_telemetry", path)} == {"system", "processes"}
    finally:
        os.unlink(path)
