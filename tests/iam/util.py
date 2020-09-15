import pytest
from botocore.exceptions import ClientError
from contextlib import contextmanager


@contextmanager
def raises_boto_code(expected_code: str):
    with pytest.raises(ClientError) as exc_info:
        yield

    actual_code = exc_info.value.response.get('Error', {}).get('Code')
    if actual_code != expected_code:
        msg = f'Invalid code, expected: {expected_code}, but got: {actual_code}.'
        raise ValueError(msg) from exc_info.value
