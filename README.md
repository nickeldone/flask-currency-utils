# flask-currency-utils

Simple currency conversion utilities for Flask applications.

## Usage
```python
from currency_utils import convert, format_currency

amount_eur = convert(100, "USD", "EUR")
print(format_currency(amount_eur, "EUR"))  # €92.50
```
