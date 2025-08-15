import httpx

async def send_to_happiboost_api(input_text: str, api_url: str, api_key: str) -> str:
    payload = {"input": input_text}
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient() as client:
        response = await client.post(api_url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json().get("output", "")

def postprocess_happiboost_output(output_text: str) -> str:
    # 江戸っ子風の末尾を固定で追加
    return f"{output_text} てやんでい、江戸っ子でい"
