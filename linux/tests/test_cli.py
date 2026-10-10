import logging

from fido2_ble_bridge.cli import configure_logging


def test_verbose_logging_never_enables_bleak_payload_logs() -> None:
    configure_logging(verbose=True)
    assert logging.getLogger("fido2_ble_bridge").isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("bleak.backends.bluezdbus.client").isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("dbus_fast").isEnabledFor(logging.DEBUG)
