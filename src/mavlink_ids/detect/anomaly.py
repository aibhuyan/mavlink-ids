"""Layer 2: anomaly / ML detector.

An Isolation Forest trained ONLY on benign flight. It learns the normal range of
the feature vectors (timing, position jumps, sequence gaps, ...) and flags events
that fall outside it. This is aimed at attacks the rules miss — GPS spoofing and
replay — which produce feature values far from anything seen in normal flight.

Isolation Forest works by randomly splitting the feature space: outliers get
"isolated" in fewer splits than normal points, so they score as anomalies. It is
unsupervised — we never show it an attack, only normal flight.
"""

from __future__ import annotations

from collections.abc import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

from mavlink_ids.alert.sink import Alert
from mavlink_ids.detect.rules import DEFAULT_ALLOWED_SYSIDS
from mavlink_ids.features.extract import FeatureExtractor
from mavlink_ids.parse.decoder import Event


class AnomalyDetector:
    """Isolation-Forest anomaly detector with a RuleEngine-style check()."""

    def __init__(
        self,
        contamination: float = 0.001,
        known_sysids: Iterable[int] = DEFAULT_ALLOWED_SYSIDS,
        random_state: int = 0,
    ):
        # contamination = the fraction of training data treated as outliers; it
        # sets the anomaly threshold. Lower = stricter = fewer false positives.
        self._contamination = contamination
        self._known_sysids = set(known_sysids)
        self._random_state = random_state
        self._model: IsolationForest | None = None
        # Stateful extractor used at check() time (see fit() for why it's reset).
        self._extractor = FeatureExtractor(self._known_sysids)

    def fit(self, benign_events: Iterable[Event]) -> AnomalyDetector:
        """Train on benign events only: learn what normal flight looks like."""
        extractor = FeatureExtractor(self._known_sysids)
        X = np.array([extractor.transform(e) for e in benign_events], dtype=float)

        self._model = IsolationForest(
            contamination=self._contamination,
            random_state=self._random_state,
        )
        self._model.fit(X)

        # check() must replay the eval stream from a clean state, so give it a
        # fresh extractor (the one above is "used up" on the training data).
        self._extractor = FeatureExtractor(self._known_sysids)
        return self

    def check(self, event: Event) -> list[Alert]:
        """Score one event; return an Alert if the model judges it anomalous."""
        if self._model is None:
            raise RuntimeError("AnomalyDetector must be fit() before check().")

        features = self._extractor.transform(event)
        x = np.array([features], dtype=float)

        # IsolationForest.predict: -1 = outlier (anomaly), 1 = inlier (normal).
        if self._model.predict(x)[0] != -1:
            return []

        # score_samples: the lower (more negative), the more anomalous.
        score = float(self._model.score_samples(x)[0])
        named = dict(zip(FeatureExtractor.FEATURE_NAMES, features))
        return [
            Alert(
                timestamp=event.timestamp,
                severity="warning",
                rule="anomaly",
                message=f"Anomalous event, unlike normal flight (score {score:.3f})",
                sysid=event.sysid,
                msg_type=event.msg_type,
                context={"score": score, "features": named},
            )
        ]

    def predict_outliers(self, events: Iterable[Event]) -> list[bool]:
        """Batch-score a stream; return True where each event is an outlier.

        Far faster than calling check() per event: it builds all feature vectors
        and runs a single vectorized prediction. Uses a fresh extractor so the
        stream is scored from a clean state, matching a live run.
        """
        if self._model is None:
            raise RuntimeError(
                "AnomalyDetector must be fit() before predict_outliers()."
            )
        extractor = FeatureExtractor(self._known_sysids)
        rows = [extractor.transform(e) for e in events]
        if not rows:
            return []
        preds = self._model.predict(np.array(rows, dtype=float))
        return [p == -1 for p in preds]
