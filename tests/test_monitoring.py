from guardrail.api.monitoring import InMemoryEventStore


def test_in_memory_monitoring_store_is_bounded_and_supports_stream_cursor():
    store = InMemoryEventStore(capacity=2)
    first = store.record_request(
        request_id="request-1",
        method="POST",
        path="/v1/sanitize",
        status_code=200,
        latency_ms=1.25,
        layer_results=[{"layer": "L1", "action": "pass", "score": 0.0}],
    )
    second = store.record_request(
        request_id="request-2",
        method="POST",
        path="/v1/isolate",
        status_code=400,
        latency_ms=2.5,
    )
    third = store.record_request(
        request_id="request-3",
        method="POST",
        path="/v1/filter",
        status_code=200,
        latency_ms=3.75,
    )

    latest = store.latest(limit=10)
    assert [event["request_id"] for event in latest] == ["request-3", "request-2"]
    assert store.after(second["event_id"]) == [third]
    assert [event["request_id"] for event in store.after(first["event_id"])] == [
        "request-2", "request-3",
    ]
    assert latest[1]["outcome"] == "blocked"
