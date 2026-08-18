import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
class Knowleadge:
    def __init__(self,knowledge_path = './tiku'):
        self.knowledge_path = knowledge_path
        self.documents = []
        self.filepaths = []
        self.vectorizer = TfidfVectorizer()
        self.tfidf_matrix = None
        self.refresh_knowledge()
    def refresh_knowledge(self):
        self.documents.clear()
        self.filepaths.clear()
        for root,dirs,files in os.walk(self.knowledge_path):
            for file in files:
                if file.endswith(".txt") or file.endswith(".py"):
                    path = os.path.join(root,file)
                    try:
                        with open(path,'r',encoding='utf-8') as f:
                            content = f.read()
                            self.documents.append(content)
                            self.filepaths.append(path)
                    except Exception:
                        pass
        if self.documents:
            self.tfidf_matrix = self.vectorizer.fit_transform(self.documents)
    def find_knowledge(self,vuln_c_code,k=5):
        if not self.documents or self.tfidf_matrix is None:
            return "本地知识库无有效信息"
        query_vec = self.vectorizer.transform([vuln_c_code])
        similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        top_k_indices = similarities.argsort()[-k:]
        knowledge_matches = []
        for index in top_k_indices:
            if similarities[index] > 0.03:
                match_text = f"题解路径{self.filepaths[index]}\n"
                match_text += f"参考题解\n{self.documents[index]}\n"
                knowledge_matches.append(match_text)
        if not knowledge_matches:
            return "未找到匹配题解"
        return '\n\n'.join(knowledge_matches)
