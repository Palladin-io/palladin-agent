import unittest

from check_rmcp_features import check_metadata


def graph(features):
    return {
        "packages": [{"name": "rmcp", "id": "rmcp@2.2.0"}],
        "resolve": {"nodes": [{"id": "rmcp@2.2.0", "features": features}]},
    }


class RmcpFeatureTests(unittest.TestCase):
    def test_accepts_server_and_async_transport(self):
        check_metadata(graph(["server", "transport-async-rw", "schemars", "dep:pastey"]))

    def test_rejects_each_affected_client_feature(self):
        for feature in ("auth", "transport-streamable-http-client",
                        "transport-streamable-http-client-reqwest",
                        "transport-streamable-http-client-unix-socket"):
            with self.subTest(feature=feature), self.assertRaises(ValueError):
                check_metadata(graph(["server", feature]))

    def test_checks_every_rmcp_version_in_resolved_graph(self):
        metadata = graph(["server"])
        metadata["packages"].append({"name": "rmcp", "id": "rmcp@2.1.0"})
        metadata["resolve"]["nodes"].append({"id": "rmcp@2.1.0", "features": ["auth"]})
        with self.assertRaises(ValueError):
            check_metadata(metadata)

    def test_rejects_incomplete_metadata_instead_of_assuming_safe(self):
        for metadata in ({}, {"packages": [], "resolve": {"nodes": []}},
                         {"packages": [{"name": "rmcp", "id": "rmcp@2.2.0"}],
                          "resolve": {"nodes": []}}):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                check_metadata(metadata)
