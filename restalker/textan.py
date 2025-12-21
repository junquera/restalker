import spacy
from collections import Counter
import string


class TextAnalysis():
    nlp = None

    def __init__(self, body):
        if TextAnalysis.nlp is None:
            try:
                TextAnalysis.nlp = spacy.load("en_core_news_md")
            except OSError:
                try:
                    TextAnalysis.nlp = spacy.load("es_core_web_md")
                except OSError:
                    TextAnalysis.nlp = spacy.load("en_core_web_sm")
        
        self.doc = TextAnalysis.nlp(body)
        
        self._extract_keywords()
    
    def _extract_keywords(self):
        # Filter relevant tokens (without stopwords...)
        keywords = [token.text.lower() for token in self.doc 
                    if not token.is_stop and not token.is_punct 
                    and not token.is_space and len(token.text.strip()) > 2]
        
        # Count frequency
        self.word_freq = Counter(keywords)
        
        # Create degree dict (for rake-nltk compatibility)
        self.word_degrees = {word: freq for word, freq in self.word_freq.items()}
        
        self.phrases = []
        for chunk in self.doc.noun_chunks:
            phrase = chunk.text.lower().strip()

            if len(phrase) > 3 and not any(c in string.punctuation for c in phrase):
                self.phrases.append(phrase)
        
        self.ranked_phrases = sorted(
            self.phrases,
            key=lambda x: sum(self.word_freq.get(word.lower(), 0) 
                             for word in x.split()),
            reverse=True
        )

    def extract_top_keyphrases(self, top=10):
        return self.ranked_phrases[:top] if self.ranked_phrases else []

    def is_keyword_present(self, keyword):
        return self.word_degrees.get(keyword.lower(), 0)
