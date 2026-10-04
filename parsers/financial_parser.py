import re

class FinancialParser:
    """
    Scans carved SMS, iMessage, and Notes to construct an automated financial ledger,
    extracting bank debit/credit transactions, OTPs, wire transfers, and digital wallet activities.
    """

    FINANCIAL_PATTERNS = [
        r'(?i)(debited|credited|transferred|withdrawn|deposited|paid|received|txn|transaction|balance|npr|inr|usd|eur|gbp|a/c|acct|otp|esewa|khalti|wise|remit|upi)',
        r'(?i)(rs\.?\s*[\d,]+(\.\d{2})?|npr\s*[\d,]+|inr\s*[\d,]+|\$\s*[\d,]+)',
        r'(?i)(otp\s*(is|:)?\s*\d{4,8}|code\s*(is|:)?\s*\d{4,8}|verification\s*code\s*\d{4,8})'
    ]

    def __init__(self, messages=None, notes=None):
        self.messages = messages or []
        self.notes = notes or []
        self.transactions = []

    def parse(self):
        # 1. Parse Messages
        for msg in self.messages:
            text = msg.get("text", "")
            if not text:
                continue

            # Check if text matches financial indicators
            is_financial = any(re.search(pat, text) for pat in self.FINANCIAL_PATTERNS)
            if not is_financial:
                continue

            # Determine transaction type
            lower_text = text.lower()
            txn_type = "Notice / Info"
            if "debited" in lower_text or "withdrawn" in lower_text or "paid" in lower_text or "sent" in lower_text:
                txn_type = "Debit (Outgoing)"
            elif "credited" in lower_text or "deposited" in lower_text or "received" in lower_text:
                txn_type = "Credit (Incoming)"
            elif "otp" in lower_text or "verification" in lower_text or "code" in lower_text:
                txn_type = "Security OTP / Auth"

            # Extract amount
            amount_match = re.search(r'(?i)(?:rs\.?|npr|inr|usd|eur|gbp|\$)\s*([\d,]+(?:\.\d{1,2})?)', text)
            amount = amount_match.group(0) if amount_match else "N/A"

            # Extract balance if present
            bal_match = re.search(r'(?i)(?:bal(?:ance)?|avl\s*bal)\s*(?:is|:)?\s*(?:rs\.?|npr|inr|usd)?\s*([\d,]+(?:\.\d{1,2})?)', text)
            balance = bal_match.group(0) if bal_match else "N/A"

            self.transactions.append({
                "source": "SMS / iMessage",
                "entity": msg.get("sender", "Unknown"),
                "timestamp_utc": msg.get("timestamp_utc", "N/A"),
                "timestamp_local": msg.get("timestamp_local", "N/A"),
                "raw_datetime": msg.get("raw_datetime"),
                "type": txn_type,
                "amount": amount,
                "balance": balance,
                "summary": text
            })

        return self.transactions
