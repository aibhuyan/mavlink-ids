"""Turn Events into numeric feature vectors for the anomaly model.

A machine-learning model needs numbers, not MAVLink messages. This extractor
walks the event stream keeping a little state (last time, last position, last
sequence number per source) and turns each event into a small fixed-length
vector. The features are chosen so that the attacks the rules miss stand out:

  * a GPS spoof produces a huge `pos_jump_m` (an impossible position leap);
  * a replay produces an abnormal `seq_gap` (a sequence number out of order).

Trained on benign flight, the model learns the normal range of these features,
so attacks land outside it.
"""

from __future__ import annotations

import math

from mavlink_ids.detect.rules import COMMAND_TYPES, DEFAULT_ALLOWED_SYSIDS
from mavlink_ids.parse.decoder import Event

# Message types that carry a latitude/longitude (in degrees * 1e7).
_POSITION_TYPES = frozenset({"GLOBAL_POSITION_INT", "GPS_RAW_INT", "GPS_INPUT"})

# The vehicle's OWN position reports. We measure jumps against these, but only
# update our "last known position" baseline from them — never from an externally
# injected GPS_INPUT, so a spoof can't poison the baseline and then frame the
# next genuine fix as a huge jump back.
_BASELINE_TYPES = frozenset({"GLOBAL_POSITION_INT", "GPS_RAW_INT"})

_EARTH_RADIUS_M = 6_371_000.0


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points, in metres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * _EARTH_RADIUS_M * math.asin(math.sqrt(a))


class FeatureExtractor:
    """Convert events to numeric vectors, keeping per-stream state."""

    FEATURE_NAMES = ("dt", "pos_jump_m", "seq_gap", "is_command", "sysid_known")

    def __init__(self, known_sysids=DEFAULT_ALLOWED_SYSIDS):
        self.known_sysids = set(known_sysids)
        self._last_time: float | None = None
        self._last_lat: float | None = None
        self._last_lon: float | None = None
        self._last_seq: dict[tuple[int, int], int] = {}  # (sysid, compid) -> seq

    def _latlon(self, event: Event) -> tuple[float, float] | None:
        """Return (lat, lon) in degrees if this event carries a position."""
        if event.msg_type not in _POSITION_TYPES:
            return None
        lat = event.fields.get("lat")
        lon = event.fields.get("lon")
        if lat is None or lon is None:
            return None
        return lat / 1e7, lon / 1e7  # MAVLink stores degrees * 1e7

    def transform(self, event: Event) -> list[float]:
        """Compute the feature vector for one event and update internal state.

        The returned list follows FEATURE_NAMES order.
        """
        # 1. time since the previous event
        dt = 0.0 if self._last_time is None else event.timestamp - self._last_time
        self._last_time = event.timestamp

        # 2. position jump from the last known location (metres)
        pos_jump = 0.0
        latlon = self._latlon(event)
        if latlon is not None:
            lat, lon = latlon
            if self._last_lat is not None and self._last_lon is not None:
                pos_jump = _haversine_m(self._last_lat, self._last_lon, lat, lon)
            # Only the vehicle's own reports update the trusted baseline.
            if event.msg_type in _BASELINE_TYPES:
                self._last_lat, self._last_lon = lat, lon

        # 3. sequence gap for this source (normal traffic increments by 1)
        key = (event.sysid, event.compid)
        last_seq = self._last_seq.get(key)
        seq_gap = 0.0 if last_seq is None else float((event.seq - last_seq) % 256)
        self._last_seq[key] = event.seq

        # 4/5. simple flags
        is_command = 1.0 if event.msg_type in COMMAND_TYPES else 0.0
        sysid_known = 1.0 if event.sysid in self.known_sysids else 0.0

        return [dt, pos_jump, seq_gap, is_command, sysid_known]
