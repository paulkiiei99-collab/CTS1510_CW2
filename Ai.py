# app/ai.py

import os

try:
    import openai
except ImportError:
    openai = None


def ask_ai(user_message, domain="general"):
    """
    Simple helper to call the OpenAI ChatCompletion API.

    - domain: "Cyber Security", "Data Science", "IT Operations", etc.
    - returns: plain text answer (string)

    If the API key or library is missing, it returns a safe fallback message.
    """

    api_key = os.getenv("OPENAI_API_KEY")

    # If OpenAI library or key is not available, return a safe message
    if openai is None or not api_key:
        return (
            "AI helper is not configured yet. "
            "Please set the OPENAI_API_KEY environment variable "
            "and install the 'openai' package."
        )

    openai.api_key = api_key

    system_prompt = (
        "You are a helpful assistant inside a university Multi-Domain "
        "Intelligence Platform. "
        "Explain clearly for a first-year CTS1510 student. "
        f"Current domain: {domain}. "
        "Use short paragraphs and simple language."
    )

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_tokens=300,
            temperature=0.3,
        )

        return response["choices"][0]["message"]["content"].strip()

    except Exception as e:
        print("Error while calling OpenAI API:", e)
        return "Sorry, the AI helper is currently unavailable. Please try again later."
