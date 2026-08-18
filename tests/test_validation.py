import pytest
from web.services.url_validation import UnsafeTarget, validate_target

@pytest.mark.asyncio
@pytest.mark.parametrize("url",["http://localhost","http://127.0.0.1","http://10.0.0.1","file:///etc/passwd","http://metadata.google.internal"])
async def test_blocks_internal_targets(url):
    with pytest.raises(UnsafeTarget): await validate_target(url,resolve_dns=False)

@pytest.mark.asyncio
async def test_allows_public_http(): assert await validate_target("https://example.com",resolve_dns=False)=="https://example.com"
