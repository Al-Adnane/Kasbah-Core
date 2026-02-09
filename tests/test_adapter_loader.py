from apps.adapters.loader import get_adapter_ids, load_adapter, adapter_spec

def test_registry_has_three():
    ids = get_adapter_ids()
    assert "ai_tool" in ids
    assert "human_finance" in ids
    assert "dao_exec" in ids

def test_load_and_describe_all():
    for adapter_id in get_adapter_ids():
        a = load_adapter(adapter_id)
        spec = adapter_spec(adapter_id)
        assert isinstance(spec, dict)
        assert "actions" in spec
        assert isinstance(spec["actions"], list)
