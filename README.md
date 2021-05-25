# Shomap
## Create visualization from Shodan query
It takes your query as an input, e.g. "hostname:gov.pl" and produces files necessary to visualize and group it accordingly by port, country, city or ISP.

article - https://offensiveosint.io/offensive-osint-s03-e07-shomap-advanced-shodan-visualization

# Installation
```
└─# git clone https://github.com/woj-ciech/Shodan_viz
└─# cd Shodan_viz
└─# pip3 install shodan
```
Put your Shodan API key in line 36 in shomap.py

# Usage
```
└─# python3 shomap.py -h                                                                                                                                            130 ⨯

    ,-:` \;',`'-, 
  .'-;_,;  ':-;_,'.
 /;   '/    ,  _`.-\ 
| '`. (`     /` ` \`|
|:.  `\`-.   \_   / |
|     (   `,  .`\ ;'|
 \     | .'     `-'/
  `.   ;/        .'
jgs `'-._____.

usage: shomap.py [-h] [-q query] [-p query]

Create visualization out of Shodan query

optional arguments:
  -h, --help            show this help message and exit
  -q query, --query query
                        Shodan query
  -p query, --pages query
                        Pages to retrieve
```

### Example
```
└─# python3 shomap.py -p 5 --query "hostname:gov.pl"
```

In the same directory run http server
```
└─# python3 -m http.server
```

Navigate to localhost:8080/shomap_viz.html

# Screenshots
![](https://raw.githubusercontent.com/woj-ciech/Shomap/main/Animation.gif)
