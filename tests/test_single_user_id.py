import httpx
import pytest

from shieldlabs import ShieldLabs, ValidationError


@pytest.mark.parametrize("ids", [["first", "second"], ["same", "same"], [], "", 1])
def test_invalid_ids_are_rejected_before_http(ids: object) -> None:
    calls = []
    with httpx.Client(transport=httpx.MockTransport(lambda r: calls.append(r))) as http:
        sdk = ShieldLabs(
            "sec_abcd1234-efgh5678-ijkl9012",
            domain_id="11111111-1111-4111-8111-111111111111",
            http_client=http,
            max_retries=0,
        )
        with pytest.raises(ValidationError, match="ids"):
            sdk.history.list("user", ids=ids)
    assert calls == []


def test_one_id_is_not_repeated_and_other_filters_are() -> None:
    calls = []

    def answer(request):
        calls.append(request)
        return httpx.Response(200, json={"data": [], "next_page_token": None})

    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        sdk = ShieldLabs(
            "sec_abcd1234-efgh5678-ijkl9012",
            domain_id="11111111-1111-4111-8111-111111111111",
            http_client=http,
            max_retries=0,
        )
        sdk.history.list("user", ids="a+b% c", risk_bands=["trusted", "dangerous"])
    assert calls[0].url.params.get_list("ids") == ["a+b% c"]
    assert calls[0].url.params.get_list("risk_bands") == ["trusted", "dangerous"]
