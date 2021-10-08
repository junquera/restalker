from rake_nltk import Rake

class TextAnalysis():

    def __init__(self, body):
        self.r = Rake()
        self.r.extract_keywords_from_text(body)

    def extract_top_keyphrases(self, top=10):
        return self.r.get_ranked_phrases()[:top]

    def is_keyword_present(self, keyword):
        return self.r.get_word_degrees()[keyword]
