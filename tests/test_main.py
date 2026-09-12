import pytest, json
from unittest.mock import patch, Mock
from csp_header_validator import main

def mock_response(headers):
    m = Mock()
    m.headers = headers
    return m

@patch('requests.get')
def test_missing_csp(mock_get, capsys):
    mock_get.return_value = mock_response({})
    with pytest.raises(SystemExit) as e:
        main(['https://example.com', '--quiet', '--threshold', '0'])
    out = json.loads(capsys.readouterr().out)
    assert out[0]['present'] is False
    assert out[0]['score'] == 0
    assert e.value.code == 0

@patch('requests.get')
def test_weak_csp(mock_get, capsys):
    hdr = {'Content-Security-Policy': "script-src *; default-src 'self'"}
    mock_get.return_value = mock_response(hdr)
    with pytest.raises(SystemExit) as e:
        main(['https://example.com', '--quiet', '--threshold', '90'])
    out = json.loads(capsys.readouterr().out)
    assert out[0]['present'] is True
    assert out[0]['score'] < 90
    assert e.value.code == 1