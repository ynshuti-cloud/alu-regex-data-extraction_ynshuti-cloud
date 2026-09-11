import os
import re
import json

# Note: The quick brown fox jumps over the lazy dog

class RegexDataProcessor:
    def __init__(self, raw_content):
        self.raw_content = raw_content
        self.sanitized_content = self._neutralize_threats(raw_content)

    def _neutralize_threats(self, input_text):
        script_guard = r'<script[\s\S]*?>[\s\S]*?</script>'
        if re.search(script_guard, input_text, re.IGNORECASE):
            print("[DEFENSE_LOG] Detected script tag attempt. Neutralized.")
            return re.sub(script_guard, '[BLOCKED_MALICIOUS_TAG]', input_text, flags=re.IGNORECASE)
        return input_text

    def parse_entities(self):
        # 1. Emails & ALU Validation
        email_rgx = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        extracted_emails = list(set(re.findall(email_rgx, self.sanitized_content)))
        
        valid_alu_suffixes = ("@alueducation.com", "@alumni.alueducation.com", "@si.alueducation.com")
        alu_verified = [addr for addr in extracted_emails if addr.lower().endswith(valid_alu_suffixes)]

        # 2. Credit Card Numbers & Masking
        card_rgx = r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'
        clean_text_for_cards = re.sub(r'[-\s]', '', self.sanitized_content)
        raw_card_matches = re.findall(card_rgx, clean_text_for_cards)
        
        redacted_cards = []
        for card_num in raw_card_matches:
            redacted_cards.append("*" * (len(card_num) - 4) + card_num[-4:])

        # 3. Phone Numbers
        phone_rgx = r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
        extracted_phones = list(set(re.findall(phone_rgx, self.sanitized_content)))

        # 4. URLs
        url_rgx = r'https?://[^\s<>"{}|\^~\[\]`]+'
        extracted_urls = list(set(re.findall(url_rgx, self.sanitized_content)))

        return {
            "metadata": {
                "total_records_processed": len(extracted_emails) + len(redacted_cards) + len(extracted_phones) + len(extracted_urls)
            },
            "results": {
                "all_emails": extracted_emails,
                "alu_emails": alu_verified,
                "masked_cards": list(set(redacted_cards)),
                "phone_numbers": extracted_phones,
                "urls": extracted_urls
            }
        }

def run_pipeline():
    root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    in_file = os.path.join(root_path, 'input', 'raw-text.txt')
    out_file = os.path.join(root_path, 'output', 'sample-output.json')

    if not os.path.exists(in_file):
        print(f"[ERROR] Cannot locate input file at: {in_file}")
        return

    with open(in_file, 'r', encoding='utf-8') as f:
        content = f.read()

    processor = RegexDataProcessor(content)
    parsed_payload = processor.parse_entities()

    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(parsed_payload, f, indent=2)

    print(f"[SUCCESS] Output stored successfully at: {out_file}")

if __name__ == "__main__":
    run_pipeline()
