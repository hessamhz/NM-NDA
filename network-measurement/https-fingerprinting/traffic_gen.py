import requests
from datetime import datetime
import pandas as pd

url = "https://www.nypost.com"
url_name = "nypost"
g_list = []
for i in range(3):
# Make the GET request
        dict = {}
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        dict["index"] = i
        dict["time"] = now
        dict["timestamp"] = timestamp
        g_list.append(dict)
        response = requests.get(url)

        response.raise_for_status()

df = pd.DataFrame(g_list)
df.to_csv(f"ta_{url_name}.csv")
    