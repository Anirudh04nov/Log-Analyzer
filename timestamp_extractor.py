import re

class TimestampExtractor:
    def __init__(self):
        self.patterns = [
            # ISO 8601
            re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
            
            # Apache/Nginx
            re.compile(r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}"),
            
            # Simple datetime
            re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?"),
            
            # Syslog
            re.compile(r"[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}")
        ]

    def extract(self, line):
        for pattern in self.patterns:
            match = pattern.search(line)
            if match:
                return match.group()
        return None