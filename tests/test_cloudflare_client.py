"""Tests for the Cloudflare API wrapper."""

import json
import pytest
from unittest.mock import Mock, patch

import cloudflare_client as cf


class TestCloudflareClient:
    """Tests for cloudflare_client module."""

    @pytest.fixture
    def api_token(self):
        return "test-token-12345"

    def test_headers(self):
        """Authorization header should have the Bearer token."""
        headers = cf._headers("my-token")
        assert headers["Authorization"] == "Bearer my-token"
        assert headers["Content-Type"] == "application/json"

    @patch("requests.request")
    def test_verify_token_success(self, mock_request, api_token):
        mock_request.return_value = Mock(
            status_code=200,
            json=lambda: {"success": True, "result": {"status": "active"}},
        )
        status = cf.verify_token(api_token)
        assert status == "active"
        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        assert args[0] == "GET"
        assert "/user/tokens/verify" in args[1]

    @patch("requests.request")
    def test_verify_token_failure(self, mock_request, api_token):
        mock_request.return_value = Mock(
            status_code=400,
            json=lambda: {
                "success": False,
                "errors": [{"code": 6003, "message": "Token invalid"}],
            },
        )
        with pytest.raises(cf.CloudflareError) as exc:
            cf.verify_token(api_token)
        assert exc.value.is_auth_error is True

    @patch("requests.request")
    def test_list_dns_records_pagination(self, mock_request, api_token):
        """list_dns_records should follow pagination."""
        mock_request.side_effect = [
            Mock(
                status_code=200,
                json=lambda: {
                    "success": True,
                    "result": [{"id": "r1", "name": "a.example.com"}],
                    "result_info": {"total_pages": 2, "page": 1},
                },
            ),
            Mock(
                status_code=200,
                json=lambda: {
                    "success": True,
                    "result": [{"id": "r2", "name": "b.example.com"}],
                    "result_info": {"total_pages": 2, "page": 2},
                },
            ),
        ]
        records = cf.list_dns_records(api_token, "zone123")
        assert len(records) == 2
        assert mock_request.call_count == 2

    @patch("requests.request")
    def test_create_dns_record(self, mock_request, api_token):
        payload = {"type": "A", "name": "test.example.com", "content": "1.2.3.4", "ttl": 1}
        mock_request.return_value = Mock(
            status_code=200,
            json=lambda: {
                "success": True,
                "result": {
                    "id": "new-record-id",
                    "type": "A",
                    "name": "test.example.com",
                    "content": "1.2.3.4",
                },
            },
        )
        result = cf.create_dns_record(api_token, "zone123", payload)
        assert result["id"] == "new-record-id"
        assert result["content"] == "1.2.3.4"

    @patch("requests.request")
    def test_patch_dns_record_content(self, mock_request, api_token):
        mock_request.return_value = Mock(
            status_code=200,
            json=lambda: {
                "success": True,
                "result": {"id": "r1", "content": "5.6.7.8"},
            },
        )
        result = cf.patch_dns_record_content(api_token, "zone123", "r1", "5.6.7.8")
        assert result["content"] == "5.6.7.8"
        # Verify the PATCH body
        _, kwargs = mock_request.call_args
        assert kwargs["json"] == {"content": "5.6.7.8"}

    @patch("requests.request")
    def test_delete_dns_record(self, mock_request, api_token):
        mock_request.return_value = Mock(
            status_code=200,
            json=lambda: {"success": True, "result": {"id": "r1"}},
        )
        cf.delete_dns_record(api_token, "zone123", "r1")
        mock_request.assert_called_once()

    @patch("requests.request")
    def test_network_error_wrapped_as_cloudflare_error(self, mock_request, api_token):
        from requests.exceptions import ConnectionError

        mock_request.side_effect = ConnectionError("Connection refused")
        with pytest.raises(cf.CloudflareError) as exc:
            cf.verify_token(api_token)
        assert "Could not reach" in str(exc.value)

    @patch("requests.request")
    def test_non_json_response(self, mock_request, api_token):
        mock_request.return_value = Mock(
            status_code=502,
            json=Mock(side_effect=ValueError("Not JSON")),
        )
        with pytest.raises(cf.CloudflareError) as exc:
            cf.verify_token(api_token)
        assert "non-JSON" in str(exc.value)
