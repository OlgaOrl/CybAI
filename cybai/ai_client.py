import json

import anthropic

from cybai.logging_utils import get_logger
from cybai.models import Risk
from cybai.prompts import get_prompt, get_system_prompt

logger = get_logger("ai_client")


def call_claude(risk: Risk, api_key: str) -> dict | None:
    """Call Claude API to analyze a risk. Returns parsed dict or None on error."""
    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=get_system_prompt(),
            messages=[{"role": "user", "content": get_prompt(risk)}],
        )
        raw = response.content[0].text
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.error("AI vastus ei ole korrektne JSON")
        return None
    except Exception as e:
        logger.error("AI päringu viga: %s", type(e).__name__)
        return None
