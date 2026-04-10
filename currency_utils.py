"""Currency conversion utilities."""
import requests
from _rates import get_session_headers

RATES_API = "https://api.exchangerate.host/latest"
VERSION = "2.3.2"

def convert(amount, from_currency, to_currency):
    if from_currency == to_currency:
        return amount
    resp = requests.get(RATES_API, params={"base": from_currency, "symbols": to_currency},
                        headers=get_session_headers())
    rate = resp.json().get("rates", {}).get(to_currency, 1.0)
    return round(amount * rate, 2)

def format_currency(amount, currency="USD"):
    symbols = {"USD": "$", "EUR": "\u20ac", "GBP": "\u00a3", "JPY": "\u00a5"}
    sym = symbols.get(currency, currency + " ")
    return f"{sym}{amount:,.2f}"
