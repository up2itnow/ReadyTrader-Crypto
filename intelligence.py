import os
import random
import time
from typing import Any, Dict, Optional

import requests

# Optional imports for Real APIs
try:
    import tweepy
except ImportError:
    tweepy = None

try:
    import praw
except ImportError:
    praw = None

try:
    from newsapi import NewsApiClient
except ImportError:
    NewsApiClient = None

def get_fear_greed_index() -> str:
    """
    Fetch the Crypto Fear & Greed Index from alternative.me.
    """
    try:
        url = "https://api.alternative.me/fng/"
        response = requests.get(url, timeout=10)
        data = response.json()
        if 'data' in data and len(data['data']) > 0:
            item = data['data'][0]
            value = item['value']
            classification = item['value_classification']
            return f"Fear & Greed Index: {value} ({classification})"
        return "Error: Could not retrieve Fear & Greed Index."
    except Exception as e:
        return f"Error fetching Fear & Greed Index: {str(e)}"

def get_market_news() -> str:
    """
    Fetch aggregated crypto market news using CryptoPanic API if available.
    """
    api_key = os.getenv("CRYPTOPANIC_API_KEY")
    if not api_key:
        return "Market News (Stub): API Key missing. Set CRYPTOPANIC_API_KEY in .env for real news."
    
    try:
        url = f"https://cryptopanic.com/api/v1/posts/?auth_token={api_key}&kind=news&filter=hot"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if 'results' in data:
            headlines = [f"{i+1}. {p['title']}" for i, p in enumerate(data['results'][:5])]
            return "CryptoPanic News:\n" + "\n".join(headlines)
        return "Error: No news found via CryptoPanic."
    except Exception as e:
        return f"Error fetching CryptoPanic news: {str(e)}"


class SentimentCache:
    def __init__(self, ttl: int = 3600):
        self.cache = {}
        self.ttl = ttl

    def get(self, symbol: str) -> Optional[Dict[str, Any]]:
        if symbol in self.cache:
            entry = self.cache[symbol]
            if time.time() - entry['time'] < self.ttl:
                return entry
        return None

    def set(self, symbol: str, score: float, description: str):
        self.cache[symbol] = {
            'time': time.time(),
            'score': score,
            'description': description
        }

_sentiment_cache = SentimentCache()

def get_cached_sentiment_score(symbol: str) -> float:
    """Return cached sentiment score or 0.0 if missing."""
    entry = _sentiment_cache.get(symbol)
    if entry:
        return entry['score']
    return 0.0

def analyze_social_sentiment(symbol: str) -> str:
    """
    Analyze social sentiment using Tweepy (X) or PRAW (Reddit) if configured.
    """
    # Check cache first (optional, but good for speed)
    # But usually this tool is called explicitly to Refresh.
    # Let's refresh every time this tool is CALLED, but get_cached_sentiment_score uses what's there.
    
    score = 0.0
    
    # 1. Twitter / X Analysis
    twitter_bearer = os.getenv("TWITTER_BEARER_TOKEN")
    twitter_result = "Twitter: API Key missing."
    
    if twitter_bearer and tweepy:
        try:
            client = tweepy.Client(bearer_token=twitter_bearer)
            # Simple search for recent tweets (read-only)
            query = f"{symbol} -is:retweet lang:en"
            tweets = client.search_recent_tweets(query=query, max_results=10)
            if tweets.data:
                texts = [t.text for t in tweets.data]
                preview = " | ".join([t[:50] + "..." for t in texts[:2]])
                twitter_result = f"Twitter (Real): Found {len(texts)} recent tweets. Preview: {preview}"
                # Mock score calculation from real data
                score += 0.2 # Arbitrary boost for finding volume
            else:
                twitter_result = "Twitter (Real): No recent tweets found."
        except Exception as e:
            twitter_result = f"Twitter Error: {str(e)}"

    # 2. Reddit Analysis
    reddit_id = os.getenv("REDDIT_CLIENT_ID")
    reddit_secret = os.getenv("REDDIT_CLIENT_SECRET")
    reddit_result = "Reddit: API Keys missing."
    
    if reddit_id and reddit_secret and praw:
        try:
            reddit = praw.Reddit(
                client_id=reddit_id,
                client_secret=reddit_secret,
                user_agent="agent_zero_crypto_bot/1.0"
            )
            # Search r/cryptocurrency
            subreddit = reddit.subreddit("cryptocurrency")
            posts = subreddit.search(symbol, limit=5, time_filter="day")
            titles = [p.title for p in posts]
            if titles:
                preview = " | ".join(titles[:2])
                reddit_result = f"Reddit (Real): Found {len(titles)} posts in r/CC. Preview: {preview}"
                score += 0.2
            else:
                reddit_result = "Reddit (Real): No recent posts found."
        except Exception as e:
            reddit_result = f"Reddit Error: {str(e)}"
            
    # Combine
    final_output = f"{twitter_result}\n{reddit_result}"
    
    if "API Key missing" in twitter_result and "API Key missing" in reddit_result:
        # Fallback to simulation
        # In simulation, we generate a random score to simulate "Live" data changing
        # Simulation-only randomness (not cryptographic).
        score = random.uniform(-0.5, 0.9)  # nosec B311
        final_output = (
            f"(Simulated) Social Sentiment for {symbol}: Score {score:.2f}. "
            "(Set TWITTER_BEARER_TOKEN or REDDIT_CLIENT_ID to use Real Data)"
        )
    
    # Update Cache
    _sentiment_cache.set(symbol, score, final_output)
    
    return final_output

def fetch_financial_news(symbol: str) -> str:
    """
    Fetch financial news using NewsAPI.
    """
    api_key = os.getenv("NEWSAPI_KEY")
    if not api_key or not NewsApiClient:
         return "(Simulated) Financial News: Bloomberg reports positive outlook. (Set NEWSAPI_KEY for real news)"
         
    try:
        newsapi = NewsApiClient(api_key=api_key)
        # Search for symbol + crypto or finance
        articles = newsapi.get_everything(q=f"{symbol} crypto", language='en', sort_by='relevancy', page_size=3)
        
        if articles['status'] == 'ok' and articles['articles']:
            headlines = [f"{i+1}. {a['title']} ({a['source']['name']})" for i, a in enumerate(articles['articles'])]
            return "Financial Headlines (NewsAPI):\n" + "\n".join(headlines)
        return "NewsAPI: No articles found."
    except Exception as e:
        return f"NewsAPI Error: {str(e)}"

