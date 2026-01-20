# Disable tensorflow warnings if present
import sys
sys.modules['tensorflow'] = None

from gliner import GLiNER
from collections import Counter
import string
import re


class TextAnalysis():
    # GLiNER model for entity extraction - loaded once and reused
    model = None

    def __init__(self, body):
        # Load GLiNER model if not already loaded
        if TextAnalysis.model is None:
            # Use nvidia's GLiNER model for PII detection
            TextAnalysis.model = GLiNER.from_pretrained('nvidia/gliner-PII')
        
        self.body = body
        self._extract_keywords()
    
    def _extract_keywords(self):
        # Simple tokenization by splitting on whitespace and punctuation
        # Filter tokens: remove short words and common punctuation
        tokens = re.findall(r'\b\w+\b', self.body.lower())
        
        # Basic stopword list (common English stopwords)
        stopwords = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
                    'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be', 
                    'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 
                    'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 
                    'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they'}
        
        # Filter relevant tokens (without stopwords and short words)
        keywords = [token for token in tokens 
                    if token not in stopwords and len(token.strip()) > 2]
        
        # Count frequency of each keyword
        self.word_freq = Counter(keywords)
        
        # Create degree dict (for compatibility with previous implementation)
        self.word_degrees = {word: freq for word, freq in self.word_freq.items()}
        
        # Extract phrases using simple n-gram approach
        self.phrases = []
        words = self.body.split()
        
        # Extract 2-4 word phrases
        for n in range(2, 5):
            for i in range(len(words) - n + 1):
                phrase = ' '.join(words[i:i+n]).lower().strip()
                # Filter phrases with punctuation and short phrases
                if len(phrase) > 3 and not any(c in string.punctuation for c in phrase):
                    self.phrases.append(phrase)
        
        # Rank phrases by the sum of word frequencies
        self.ranked_phrases = sorted(
            self.phrases,
            key=lambda x: sum(self.word_freq.get(word.lower(), 0) 
                             for word in x.split()),
            reverse=True
        )

    def extract_top_keyphrases(self, top=10):
        """Extract top N keyphrases from the text"""
        return self.ranked_phrases[:top] if self.ranked_phrases else []

    def is_keyword_present(self, keyword):
        """Check if a keyword is present in the text (returns frequency)"""
        return self.word_degrees.get(keyword.lower(), 0)
