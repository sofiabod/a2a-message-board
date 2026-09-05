def pytest_collection_modifyitems(config, items):
    if config.getoption("-m"):
        return
    skip = __import__("pytest").mark.skip(reason="real Modal VM; run with -m modal")
    for item in items:
        if "modal" in item.keywords:
            item.add_marker(skip)
