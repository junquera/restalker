import yake
import spacy
from collections import Counter
from .spacy_singleton import get_spacy_model

class TextAnalysis():

    def __init__(self, body):
        self.body = body
        self.kw_extractor = yake.KeywordExtractor(
            lan="en", 
            n=3, 
            dedupLim=0.7, 
            top=20
        )
        
        # Try to load spaCy model for additional analysis
        self.nlp = get_spacy_model()

    def extract_top_keyphrases(self, top=10):
        """Extract top keyphrases using YAKE algorithm"""
        keywords = self.kw_extractor.extract_keywords(self.body)
        # YAKE returns tuples of (score, keyphrase), we want just the keyphrases
        return [kw[1] for kw in keywords[:top]]

    def is_keyword_present(self, keyword):
        """Check if a keyword is present in the text and return its frequency"""
        keyword_lower = keyword.lower()
        body_lower = self.body.lower()
        
        # Simple frequency count
        count = body_lower.count(keyword_lower)
        
        # If spaCy is available, also check for lemmatized forms
        if self.nlp and count == 0:
            try:
                doc = self.nlp(self.body)
                lemmatized_body = " ".join([token.lemma_.lower() for token in doc])
                count = lemmatized_body.count(keyword_lower)
            except:
                pass  # If spaCy processing fails, just return the simple count
            
        return count
